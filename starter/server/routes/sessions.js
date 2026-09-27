import { newId, nowIso } from '../db.js';
import { send, badRequest, notFound, conflict, deviceBusy } from '../http.js';
import { assertCan, assertCanStartSession } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { snapshotAuthority, sessionExpiry } from '../lifecycle.js';

const MODES = ['view', 'control', 'terminal'];

function sweepExpired(db, orgId) {
  const at = nowIso();
  const ids = db
    .prepare("SELECT id FROM sessions WHERE org_id=? AND state='active' AND expires_at <= ?")
    .all(orgId, at)
    .map((r) => r.id);

  const stmt = db.prepare("UPDATE sessions SET state='ended', ended_at=?, end_reason='session_expired' WHERE id=?");
  for (const id of ids) stmt.run(at, id);
  return ids;
}

export function registerSessionRoutes(router, { db }) {
  // POST /v1/orgs/:org/sessions  { deviceId, mode }
  router.post('/v1/orgs/:org/sessions', (ctx, params, res) => {
    const deviceId = String(ctx.body?.deviceId ?? '');
    const mode = String(ctx.body?.mode ?? '');

    if (!MODES.includes(mode)) {
      throw badRequest(`mode must be one of: ${MODES.join(', ')}`);
    }

    const device = db
      .prepare('SELECT * FROM devices WHERE id=? AND org_id=? AND deleted_at IS NULL')
      .get(deviceId, params.org);
    if (!device) throw notFound();

    auditDenials(db, ctx, { action: 'session.start', targetType: 'device', targetId: deviceId }, () => {
      assertCanStartSession(db, ctx, mode, deviceId);
    });

    sweepExpired(db, params.org);

    const id = newId('ses');
    try {
      db.prepare(
        `INSERT INTO sessions (id,org_id,user_id,device_id,mode,state,authorized_by,expires_at)
         VALUES (?,?,?,?,?,'active',?,?)`
      ).run(
        id,
        params.org,
        ctx.userId,
        deviceId,
        mode,
        snapshotAuthority(db, { userId: ctx.userId, orgId: params.org, deviceId }),
        sessionExpiry(db, params.org)
      );
    } catch (err) {
      if (String(err.code).startsWith('SQLITE_CONSTRAINT')) {
        const holder = db
          .prepare(
            "SELECT id,user_id FROM sessions WHERE device_id=? AND state='active' AND mode IN ('control','terminal')"
          )
          .get(deviceId);
        throw deviceBusy(`device is already held by session ${holder?.id ?? 'unknown'}`);
      }
      throw err;
    }

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'session.start',
      targetType: 'device',
      targetId: deviceId,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 201, { id, deviceId, mode, state: 'active' });
  });

  // GET /v1/orgs/:org/sessions
  router.get('/v1/orgs/:org/sessions', (ctx, params, res) => {
    assertCan(db, ctx, 'session:view');
    sweepExpired(db, params.org);

    const sessions = db
      .prepare(
        `SELECT s.id, s.user_id, u.name AS user_name, s.device_id, d.name AS device_name,
                s.mode, s.state, s.end_reason, s.started_at, s.ended_at, s.expires_at
           FROM sessions s
           JOIN users u ON u.id = s.user_id
           JOIN devices d ON d.id = s.device_id
          WHERE s.org_id = ? ORDER BY s.started_at DESC LIMIT 200`
      )
      .all(params.org);

    send(res, 200, { sessions });
  });

  // GET /v1/sessions/:id
  router.get('/v1/sessions/:id', (ctx, params, res) => {
    sweepExpired(db, ctx.orgId);
    const session = db.prepare('SELECT * FROM sessions WHERE id=? AND org_id=?').get(params.id, ctx.orgId);
    if (!session) throw notFound();

    if (session.user_id !== ctx.userId) {
      assertCan(db, ctx, 'session:view');
    }

    send(res, 200, session);
  });

  // DELETE /v1/sessions/:id
  router.delete('/v1/sessions/:id', (ctx, params, res) => {
    sweepExpired(db, ctx.orgId);
    const session = db.prepare('SELECT * FROM sessions WHERE id=? AND org_id=?').get(params.id, ctx.orgId);
    if (!session) throw notFound();

    const isOwn = session.user_id === ctx.userId;
    if (!isOwn) {
      auditDenials(db, ctx, { action: 'session.terminate', targetType: 'session', targetId: params.id }, () => {
        assertCan(db, ctx, 'session:terminate');
      });
    }

    if (session.state === 'ended') {
      throw conflict('session already ended');
    }

    db.prepare("UPDATE sessions SET state='ended', ended_at=?, end_reason=? WHERE id=?").run(
      nowIso(),
      isOwn ? 'user_stopped' : 'admin_terminated',
      params.id
    );

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: isOwn ? 'session.stop' : 'session.terminate',
      targetType: 'session',
      targetId: params.id,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 204, undefined);
  });
}
