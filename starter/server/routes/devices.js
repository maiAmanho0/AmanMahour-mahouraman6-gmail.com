import { newId, nowIso } from '../db.js';
import { send, badRequest, notFound, forbidden } from '../http.js';
import { assertCan, resolve, resolveDevices } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { endActiveSessions } from '../lifecycle.js';

const KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];

function requireDevice(db, orgId, deviceId) {
  const device = db
    .prepare('SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL')
    .get(deviceId, orgId);
  if (!device) throw notFound();
  return device;
}

export function registerDeviceRoutes(router, { db }) {
  // GET /v1/orgs/:org/devices — device:list gates the endpoint, device:view gates row inclusion
  router.get('/v1/orgs/:org/devices', (ctx, params, res) => {
    assertCan(db, ctx, 'device:list');

    const rows = db
      .prepare(
        `SELECT id, name, kind, online, created_at FROM devices
          WHERE org_id = ? AND deleted_at IS NULL ORDER BY name`
      )
      .all(params.org);

    const { byDevice } = resolveDevices(db, {
      userId: ctx.userId,
      orgId: params.org,
      deviceIds: rows.map((d) => d.id),
    });

    const devices = [];
    for (const device of rows) {
      const permissions = byDevice[device.id];
      if (permissions?.['device:view']?.effect !== 'allow') continue; // row exclusion, not redaction
      devices.push({ ...device, online: device.online === 1, permissions });
    }

    send(res, 200, { devices });
  });

  // GET /v1/orgs/:org/devices/:id — device:view
  router.get('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const device = requireDevice(db, params.org, params.id);
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: params.org, deviceId: device.id });
    if (permissions?.['device:view']?.effect !== 'allow') throw notFound(); // invisible 404, not 403
    send(res, 200, { ...device, online: device.online === 1, permissions });
  });

  // POST /v1/orgs/:org/devices — device:provision
  router.post('/v1/orgs/:org/devices', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'device.create', targetType: 'device' }, () => {
      assertCan(db, ctx, 'device:provision');
    });

    const name = String(ctx.body?.name ?? '').trim();
    const kind = String(ctx.body?.kind ?? '');
    if (name.length < 1 || name.length > 200) throw badRequest('name must be 1-200 characters');
    if (!KINDS.includes(kind)) throw badRequest(`kind must be one of: ${KINDS.join(', ')}`);

    const id = newId('dev');
    db.prepare('INSERT INTO devices (id,org_id,name,kind,online) VALUES (?,?,?,?,?)').run(
      id,
      params.org,
      name,
      kind,
      ctx.body?.online ? 1 : 0
    );
    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'device.create',
      targetType: 'device',
      targetId: id,
      result: 'allow',
      requestId: ctx.requestId,
    });
    send(res, 201, { id, name, kind });
  });

  // PATCH /v1/orgs/:org/devices/:id — device:update
  router.patch('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const device = requireDevice(db, params.org, params.id);
    auditDenials(db, ctx, { action: 'device.update', targetType: 'device', targetId: device.id }, () => {
      assertCan(db, ctx, 'device:update', device.id);
    });

    const name = ctx.body?.name === undefined ? device.name : String(ctx.body.name).trim();
    if (name.length < 1 || name.length > 200) throw badRequest('name must be 1-200 characters');
    const online = ctx.body?.online === undefined ? device.online : ctx.body.online ? 1 : 0;

    db.prepare('UPDATE devices SET name=?, online=? WHERE id=?').run(name, online, device.id);
    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'device.update',
      targetType: 'device',
      targetId: device.id,
      result: 'allow',
      requestId: ctx.requestId,
    });
    send(res, 200, { id: device.id, name, online: online === 1 });
  });

  // DELETE /v1/orgs/:org/devices/:id — device:provision (device-scoped decommissioning)
  router.delete('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const device = requireDevice(db, params.org, params.id);
    auditDenials(db, ctx, { action: 'device.decommission', targetType: 'device', targetId: device.id }, () => {
      assertCan(db, ctx, 'device:provision', device.id);
    });

    const tx = db.transaction(() => {
      db.prepare('UPDATE devices SET deleted_at=? WHERE id=?').run(nowIso(), device.id);
      endActiveSessions(db, { orgId: params.org, deviceId: device.id, reason: 'device_transferred' });
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: 'device.decommission',
        targetType: 'device',
        targetId: device.id,
        result: 'allow',
        requestId: ctx.requestId,
      });
    });
    tx();
    send(res, 204, undefined);
  });

  // POST /v1/orgs/:org/devices/:id/transfer — device:provision in both source and target orgs
  router.post('/v1/orgs/:org/devices/:id/transfer', (ctx, params, res) => {
    const device = requireDevice(db, params.org, params.id);
    const targetOrgId = String(ctx.body?.targetOrgId ?? '');

    auditDenials(db, ctx, { action: 'device.transfer', targetType: 'device', targetId: device.id }, () => {
      assertCan(db, ctx, 'device:provision', device.id);
    });

    const target = db.prepare('SELECT id FROM organizations WHERE id=? AND deleted_at IS NULL').get(targetOrgId);
    if (!target) throw notFound();

    const targetPerms = resolve(db, { userId: ctx.userId, orgId: targetOrgId });
    if (targetPerms.permissions?.['device:provision']?.effect !== 'allow') {
      throw forbidden('you need device:provision in the target organization', 'missing_permission');
    }

    const tx = db.transaction(() => {
      db.prepare('UPDATE devices SET org_id=? WHERE id=?').run(targetOrgId, device.id);
      // Drop grants associated with device in the old org
      db.prepare('DELETE FROM grant_permissions WHERE grant_id IN (SELECT id FROM grants WHERE device_id=?)').run(
        device.id
      );
      db.prepare('DELETE FROM grants WHERE device_id=?').run(device.id);

      endActiveSessions(db, { orgId: params.org, deviceId: device.id, reason: 'device_transferred' });
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: 'device.transfer',
        targetType: 'device',
        targetId: device.id,
        result: 'allow',
        requestId: ctx.requestId,
      });
    });
    tx();

    send(res, 200, { id: device.id, orgId: targetOrgId });
  });
}
