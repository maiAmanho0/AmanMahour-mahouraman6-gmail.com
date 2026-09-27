import { newId, nowIso, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound, conflict, forbidden, selfRoleChange, normalizeTs, gone } from '../http.js';
import { assertCan, resolve, assertMayGrant } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import {
  assertCanModify, assertNotLastOwner, endActiveSessions, roleRanks, assertRoleExists,
} from '../lifecycle.js';
import { hashPassword, hashInviteToken, newInviteToken } from '../auth.js';

// Pagination: out-of-bounds is a 400, not a silent clamp (per spec).
const MAX_LIMIT = 200;
function pagination(query) {
  const rawLimit = query?.get('limit');
  const rawOffset = query?.get('offset');

  const limit = rawLimit === null || rawLimit === undefined ? 50 : Number(rawLimit);
  const offset = rawOffset === null || rawOffset === undefined ? 0 : Number(rawOffset);

  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) {
    throw badRequest(`limit must be an integer between 1 and ${MAX_LIMIT}`);
  }
  if (!Number.isInteger(offset) || offset < 0) {
    throw badRequest('offset must be a non-negative integer');
  }
  return { limit, offset };
}

const THEMES = ['cobalt', 'amber', 'moss', 'plum', 'rust', 'teal'];
const INVITE_TTL_DAYS = 7;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function registerOrgRoutes(router, { db }) {
  // --- orgs ------------------------------------------------------------------

  // GET /v1/orgs — every org the caller belongs to (cross-org is legitimate here).
  router.get('/v1/orgs', (ctx, _p, res) => {
    const orgs = db.prepare(
      `SELECT o.id, o.name, o.theme, m.role, m.status
         FROM memberships m JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
        ORDER BY o.name`
    ).all(ctx.userId);
    send(res, 200, { orgs });
  });

  // POST /v1/orgs — create an org; creator becomes sole owner.
  router.post('/v1/orgs', (ctx, _p, res) => {
    const name = String(ctx.body?.name ?? '').trim();
    if (name.length < 1 || name.length > 200) throw badRequest('name must be 1-200 characters');

    const orgId = newId('org');
    const theme = THEMES.includes(ctx.body?.theme)
      ? ctx.body.theme
      : THEMES[db.prepare('SELECT count(*) AS n FROM organizations').get().n % THEMES.length];

    const tx = db.transaction(() => {
      db.prepare('INSERT INTO organizations (id,name,theme) VALUES (?,?,?)').run(orgId, name, theme);
      db.prepare(
        `INSERT INTO memberships (id,org_id,user_id,role,status,joined_at) VALUES (?,?,?,'owner','active',?)`
      ).run(newId('mem'), orgId, ctx.userId, nowIso());
      audit(db, { orgId, actorId: ctx.userId, action: 'org.create', targetType: 'org', targetId: orgId, result: 'allow', requestId: ctx.requestId });
    });
    tx();

    send(res, 201, { id: orgId, name, theme, role: 'owner' });
  });

  router.patch('/v1/orgs/:org', (ctx, params, res) => {
    assertCan(db, ctx, 'org:update');
    const name = String(ctx.body?.name ?? '').trim();
    if (name.length < 1 || name.length > 200) throw badRequest('name must be 1-200 characters');

    db.prepare('UPDATE organizations SET name = ? WHERE id = ?').run(name, params.org);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'org.update', targetType: 'org', targetId: params.org, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { id: params.org, name });
  });

  router.delete('/v1/orgs/:org', (ctx, params, res) => {
    assertCan(db, ctx, 'org:delete');
    db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(nowIso(), params.org);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'org.delete', targetType: 'org', targetId: params.org, result: 'allow', requestId: ctx.requestId });
    send(res, 204, undefined);
  });

  // --- members ---------------------------------------------------------------
  // NOTE: /members/me is registered BEFORE /members/:userId — first match wins.

  router.get('/v1/orgs/:org/members', (ctx, params, res) => {
    assertCan(db, ctx, 'user:read');
    const members = db.prepare(
      `SELECT u.id, u.email, u.name, m.role, m.status, m.perm_version, m.joined_at
         FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND m.status != 'removed'
        ORDER BY u.name`
    ).all(params.org);
    send(res, 200, { members });
  });

  // Leave an org (self-service, no user:remove needed — cannot orphan the org).
  router.delete('/v1/orgs/:org/members/me', (ctx, params, res) => {
    assertNotLastOwner(db, params.org, ctx.userId);
    removeMembership(db, ctx, params.org, ctx.userId, 'member.leave');
    send(res, 204, undefined);
  });

  router.patch('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    const { userId } = params;
    const role = ctx.body?.role;

    if (userId === ctx.userId) throw selfRoleChange();
    if (typeof role !== 'string') throw badRequest('role is required');
    assertRoleExists(db, role);

    auditDenials(db, ctx, { action: 'user.role.update', targetType: 'user', targetId: userId }, () => {
      assertCan(db, ctx, 'user:role:update');
    });

    const target = db.prepare('SELECT * FROM memberships WHERE org_id=? AND user_id=?').get(params.org, userId);
    if (!target || target.status === 'removed') throw notFound();

    assertCanModify(db, ctx.role, target.role);
    if (role === 'owner' && ctx.role !== 'owner') {
      throw forbidden('only an owner may assign the owner role', 'cannot_confer_owner');
    }
    if (target.role === 'owner' && role !== 'owner') assertNotLastOwner(db, params.org, userId);

    const tx = db.transaction(() => {
      db.prepare('UPDATE memberships SET role = ? WHERE org_id=? AND user_id=?').run(role, params.org, userId);
      bumpPermVersion(db, { orgId: params.org, userId });
      // Grandfathering: permission change does NOT end active sessions (§7.1).
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'user.role.update', targetType: 'user', targetId: userId, result: 'allow', requestId: ctx.requestId });
    });
    tx();

    send(res, 200, { id: userId, role });
  });

  router.post('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    setMembershipStatus(db, ctx, params.org, params.userId, 'suspended', 'member.suspend');
    send(res, 200, { id: params.userId, status: 'suspended' });
  });

  router.delete('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    setMembershipStatus(db, ctx, params.org, params.userId, 'active', 'member.reinstate');
    send(res, 200, { id: params.userId, status: 'active' });
  });

  router.delete('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    removeMembership(db, ctx, params.org, params.userId, 'member.remove');
    send(res, 204, undefined);
  });

  // --- effective permissions -------------------------------------------------

  // A user may always read their own; reading someone else's needs user:read.
  router.get('/v1/orgs/:org/users/:userId/effective', (ctx, params, res) => {
    const isSelf = params.userId === ctx.userId;
    if (!isSelf) assertCan(db, ctx, 'user:read');

    const membership = db.prepare('SELECT role,status FROM memberships WHERE org_id=? AND user_id=?')
      .get(params.org, params.userId);
    if (!membership) throw notFound();

    const deviceId = ctx.query?.get('deviceId') ?? null;
    const resolved = resolve(db, { userId: params.userId, orgId: params.org, deviceId });
    send(res, 200, { userId: params.userId, orgId: params.org, deviceId, ...resolved });
  });

  // --- invites ---------------------------------------------------------------

  router.post('/v1/orgs/:org/invites', (ctx, params, res) => {
    const email = String(ctx.body?.email ?? '').trim().toLowerCase();
    const role = String(ctx.body?.role ?? '');

    if (!EMAIL.test(email) || email.length > 320) throw badRequest('a valid email is required');
    assertRoleExists(db, role);

    auditDenials(db, ctx, { action: 'user.invite', targetType: 'email', targetId: email }, () => {
      assertCan(db, ctx, 'user:invite');
    });

    if (role === 'owner' && ctx.role !== 'owner') {
      throw forbidden('only an owner may invite an owner', 'cannot_confer_owner');
    }
    assertCanModify(db, ctx.role, role);

    const existing = db.prepare(
      `SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND u.email = ? AND m.status != 'removed'`
    ).get(params.org, email);
    if (existing) throw conflict('that email already has a membership in this org');

    const live = db.prepare(
      'SELECT 1 FROM invites WHERE org_id=? AND email=? AND accepted_at IS NULL AND revoked_at IS NULL'
    ).get(params.org, email);
    if (live) throw conflict('a pending invite already exists for that email');

    const raw = newInviteToken();
    const inviteId = newId('inv');

    const tx = db.transaction(() => {
      db.prepare(
        `INSERT INTO invites (id,org_id,email,role,token_hash,invited_by,expires_at) VALUES (?,?,?,?,?,?,?)`
      ).run(inviteId, params.org, email, role, hashInviteToken(raw), ctx.userId,
            new Date(Date.now() + INVITE_TTL_DAYS * 864e5).toISOString());

      // Membership row in 'invited' state so the member list can show pending invites.
      const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
      if (user) {
        db.prepare(
          `INSERT OR IGNORE INTO memberships (id,org_id,user_id,role,status,invited_by) VALUES (?,?,?,?,'invited',?)`
        ).run(newId('mem'), params.org, user.id, role, ctx.userId);
      }
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'user.invite', targetType: 'email', targetId: email, result: 'allow', requestId: ctx.requestId });
    });
    tx();

    send(res, 201, {
      id: inviteId,
      email,
      role,
      expiresAt: new Date(Date.now() + INVITE_TTL_DAYS * 864e5).toISOString(),
      inviteToken: raw,
    });
  });

  router.get('/v1/orgs/:org/invites', (ctx, params, res) => {
    assertCan(db, ctx, 'user:invite');
    const invites = db.prepare(
      `SELECT id, email, role, expires_at, accepted_at, revoked_at, created_at
         FROM invites WHERE org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL
        ORDER BY created_at DESC`
    ).all(params.org);
    send(res, 200, { invites });
  });

  router.delete('/v1/orgs/:org/invites/:id', (ctx, params, res) => {
    assertCan(db, ctx, 'user:invite');
    const invite = db.prepare('SELECT * FROM invites WHERE id=? AND org_id=?').get(params.id, params.org);
    if (!invite) throw notFound();
    if (invite.accepted_at) throw conflict('invite was already accepted; remove the member instead');

    db.prepare('UPDATE invites SET revoked_at=? WHERE id=?').run(nowIso(), params.id);
    db.prepare("DELETE FROM memberships WHERE org_id=? AND user_id=(SELECT id FROM users WHERE email=?) AND status='invited'")
      .run(params.org, invite.email);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'user.invite.revoke', targetType: 'invite', targetId: params.id, result: 'allow', requestId: ctx.requestId });
    send(res, 204, undefined);
  });

  // --- invite redemption (PUBLIC — the token is the credential) --------------

  router.get('/v1/invites/:token', (ctx, params, res) => {
    const invite = lookupInvite(db, params.token);
    send(res, 200, {
      email: invite.email,
      role: invite.role,
      orgName: invite.org_name,
      expiresAt: invite.expires_at,
    });
  });

  router.post('/v1/invites/:token/accept', (ctx, params, res) => {
    const invite = lookupInvite(db, params.token);
    const name = String(ctx.body?.name ?? '').trim();
    const password = String(ctx.body?.password ?? '');
    if (name.length < 1 || name.length > 200) throw badRequest('name must be 1-200 characters');
    if (password.length < 8) throw badRequest('password must be at least 8 characters');

    const tx = db.transaction(() => {
      // Atomic single-use claim. Under two concurrent accepts, exactly one UPDATE
      // affects a row; the other sees changes === 0 and gets a 409.
      const claim = db.prepare(
        `UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL`
      ).run(nowIso(), null, invite.id);
      if (claim.changes !== 1) throw conflict('invite has already been used');

      // Existing platform user? Attach a membership to them. Do NOT create a duplicate.
      let user = db.prepare('SELECT * FROM users WHERE email = ?').get(invite.email);
      if (!user) {
        const id = newId('usr');
        db.prepare('INSERT INTO users (id,email,name,password_hash) VALUES (?,?,?,?)')
          .run(id, invite.email, name, hashPassword(password));
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
      }

      const membership = db.prepare('SELECT * FROM memberships WHERE org_id=? AND user_id=?')
        .get(invite.org_id, user.id);

      if (membership) {
        if (membership.status === 'active') throw conflict('you are already a member of this org');
        db.prepare("UPDATE memberships SET status='active', role=?, joined_at=? WHERE id=?")
          .run(invite.role, nowIso(), membership.id);
        bumpPermVersion(db, { orgId: invite.org_id, userId: user.id });
      } else {
        db.prepare(
          `INSERT INTO memberships (id,org_id,user_id,role,status,invited_by,joined_at) VALUES (?,?,?,?,'active',?,?)`
        ).run(newId('mem'), invite.org_id, user.id, invite.role, invite.invited_by, nowIso());
      }

      db.prepare('UPDATE invites SET accepted_by = ? WHERE id = ?').run(user.id, invite.id);
      audit(db, { orgId: invite.org_id, actorId: user.id, action: 'user.invite.accept', targetType: 'invite', targetId: invite.id, result: 'allow', requestId: ctx.requestId });

      return { userId: user.id, orgId: invite.org_id, role: invite.role };
    });

    const result = tx();
    send(res, 200, { userId: result.userId, orgId: result.orgId, role: result.role });
  });

  // --- grants ----------------------------------------------------------------

  router.get('/v1/orgs/:org/grants', (ctx, params, res) => {
    assertCan(db, ctx, 'user:read');
    const userId = ctx.query?.get('userId');
    const rows = db.prepare(
      `SELECT g.id, g.user_id, g.device_id, g.effect, g.starts_at, g.expires_at, g.created_at,
              group_concat(gp.permission) AS permissions
         FROM grants g JOIN grant_permissions gp ON gp.grant_id = g.id
        WHERE g.org_id = ? AND g.revoked_at IS NULL ${userId ? 'AND g.user_id = ?' : ''}
        GROUP BY g.id ORDER BY g.created_at DESC`
    ).all(...(userId ? [params.org, userId] : [params.org]));

    send(res, 200, { grants: rows.map((r) => ({ ...r, permissions: r.permissions.split(',') })) });
  });

  // POST /v1/orgs/:org/grants — grants are a delta in EITHER direction (D3).
  router.post('/v1/orgs/:org/grants', (ctx, params, res) => {
    const { userId, deviceId = null, effect, permissions, startsAt = null, expiresAt = null } = ctx.body ?? {};

    auditDenials(db, ctx, { action: 'grant.create', targetType: 'user', targetId: userId }, () => {
      assertCan(db, ctx, 'grant:create');
    });

    // D9: no self-grants, no privilege laundering.
    if (userId === ctx.userId) throw forbidden('you cannot create a grant for yourself', 'self_grant');

    if (typeof userId !== 'string' || userId.length === 0) throw badRequest('userId is required');
    if (deviceId !== null && typeof deviceId !== 'string') throw badRequest('deviceId must be a string or null');
    if (!Array.isArray(permissions) || permissions.length === 0) {
      throw badRequest('permissions must be a non-empty array');
    }
    if (!permissions.every((p) => typeof p === 'string' && p.length > 0)) {
      throw badRequest('permissions must be non-empty strings');
    }
    if (effect !== 'allow' && effect !== 'deny') throw badRequest("effect must be 'allow' or 'deny'");

    const wanted = [...new Set(permissions)];

    const target = db.prepare("SELECT 1 FROM memberships WHERE org_id=? AND user_id=? AND status='active'")
      .get(params.org, userId);
    if (!target) throw notFound();

    if (deviceId !== null) {
      const device = db.prepare('SELECT id FROM devices WHERE id=? AND org_id=? AND deleted_at IS NULL')
        .get(deviceId, params.org);
      if (!device) throw notFound();
    }

    const now = nowIso();
    const startsAtN = normalizeTs(startsAt, 'startsAt');
    const expiresAtN = normalizeTs(expiresAt, 'expiresAt');
    if (expiresAtN !== null && expiresAtN <= now) throw badRequest('expiresAt is in the past', 'expired_grant');
    if (startsAtN !== null && expiresAtN !== null && expiresAtN <= startsAtN) {
      throw badRequest('expiresAt must be after startsAt');
    }

    // D9 — no laundering: you can only hand out authority you hold at this scope.
    assertMayGrant(db, ctx, wanted, deviceId);

    const id = newId('grt');
    const tx = db.transaction(() => {
      db.prepare(
        `INSERT INTO grants (id,org_id,user_id,device_id,effect,starts_at,expires_at,created_by) VALUES (?,?,?,?,?,?,?,?)`
      ).run(id, params.org, userId, deviceId, effect, startsAtN, expiresAtN, ctx.userId);

      // The FK to permission_patterns rejects 'device:teleport' etc. Map to 400 (D19).
      const stmt = db.prepare('INSERT INTO grant_permissions (grant_id,permission) VALUES (?,?)');
      for (const p of wanted) {
        try {
          stmt.run(id, p);
        } catch (err) {
          if (String(err.code).includes('FOREIGNKEY') || String(err.message).includes('FOREIGN KEY')) {
            throw badRequest(`unknown permission: ${p}`, 'unknown_permission');
          }
          throw err;
        }
      }

      // Permission change takes effect on the NEXT request — sessions are grandfathered.
      bumpPermVersion(db, { orgId: params.org, userId });
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'grant.create', targetType: 'user', targetId: userId, result: 'allow', requestId: ctx.requestId });
    });
    tx();

    send(res, 201, { id, userId, deviceId, effect, permissions: wanted });
  });

  router.delete('/v1/orgs/:org/grants/:id', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'grant.revoke', targetType: 'grant', targetId: params.id }, () => {
      assertCan(db, ctx, 'grant:revoke');
    });

    const grant = db.prepare('SELECT * FROM grants WHERE id=? AND org_id=? AND revoked_at IS NULL')
      .get(params.id, params.org);
    if (!grant) throw notFound();

    const tx = db.transaction(() => {
      db.prepare('UPDATE grants SET revoked_at=? WHERE id=?').run(nowIso(), params.id);
      bumpPermVersion(db, { orgId: params.org, userId: grant.user_id });
      // Deliberately NOT ending sessions — grandfathering applies (§7.1).
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'grant.revoke', targetType: 'grant', targetId: params.id, result: 'allow', requestId: ctx.requestId });
    });
    tx();

    send(res, 204, undefined);
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function setMembershipStatus(db, ctx, orgId, userId, status, action) {
  auditDenials(db, ctx, { action, targetType: 'user', targetId: userId }, () => {
    assertCan(db, ctx, 'user:remove');
  });

  const target = db.prepare('SELECT * FROM memberships WHERE org_id=? AND user_id=?').get(orgId, userId);
  if (!target || target.status === 'removed') throw notFound();
  if (target.role === 'owner' && status !== 'active') assertNotLastOwner(db, orgId, userId);
  assertCanModify(db, ctx.role, target.role);

  const tx = db.transaction(() => {
    db.prepare('UPDATE memberships SET status = ? WHERE org_id=? AND user_id=?').run(status, orgId, userId);
    bumpPermVersion(db, { orgId, userId });
    // Suspension cascades (account integrity, not a permission tweak — §7.2).
    if (status !== 'active') endActiveSessions(db, { orgId, userId, reason: 'user_suspended' });
    audit(db, { orgId, actorId: ctx.userId, action, targetType: 'user', targetId: userId, result: 'allow', requestId: ctx.requestId });
  });
  tx();
}

function removeMembership(db, ctx, orgId, userId, action) {
  if (action === 'member.remove') {
    auditDenials(db, ctx, { action, targetType: 'user', targetId: userId }, () => {
      assertCan(db, ctx, 'user:remove');
    });
  }

  const target = db.prepare('SELECT * FROM memberships WHERE org_id=? AND user_id=?').get(orgId, userId);
  if (!target || target.status === 'removed') throw notFound();
  if (target.role === 'owner') assertNotLastOwner(db, orgId, userId);
  if (userId !== ctx.userId) assertCanModify(db, ctx.role, target.role);

  const tx = db.transaction(() => {
    // The USER ROW IS NEVER DELETED (D15).
    db.prepare("UPDATE memberships SET status='removed' WHERE org_id=? AND user_id=?").run(orgId, userId);
    bumpPermVersion(db, { orgId, userId });
    endActiveSessions(db, { orgId, userId, reason: 'membership_removed' });
    audit(db, { orgId, actorId: ctx.userId, action, targetType: 'user', targetId: userId, result: 'allow', requestId: ctx.requestId });
  });
  tx();
}

function lookupInvite(db, rawToken) {
  if (!rawToken || rawToken.length < 16) throw notFound();

  const invite = db.prepare(
    `SELECT i.*, o.name AS org_name, o.deleted_at AS org_deleted
       FROM invites i JOIN organizations o ON o.id = i.org_id
      WHERE i.token_hash = ?`
  ).get(hashInviteToken(rawToken));

  if (!invite) throw notFound();
  if (invite.org_deleted) throw notFound();
  if (invite.revoked_at) throw gone('this invite was revoked');
  if (invite.accepted_at) throw conflict('this invite has already been used');
  if (invite.expires_at <= nowIso()) throw gone('this invite has expired');

  return invite;
}
