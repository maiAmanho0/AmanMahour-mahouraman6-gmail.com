import { send, badRequest } from '../http.js';
import { assertCan } from '../permissions.js';

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

export function registerAuditRoutes(router, { db }) {
  // GET /v1/orgs/:org/audit
  router.get('/v1/orgs/:org/audit', (ctx, params, res) => {
    assertCan(db, ctx, 'audit:read');
    const { limit, offset } = pagination(ctx.query);
    const since = ctx.query?.get('since');

    const rows = since
      ? db
          .prepare(
            'SELECT * FROM audit_events WHERE org_id = ? AND at >= ? ORDER BY at DESC LIMIT ? OFFSET ?'
          )
          .all(params.org, since, limit, offset)
      : db
          .prepare('SELECT * FROM audit_events WHERE org_id = ? ORDER BY at DESC LIMIT ? OFFSET ?')
          .all(params.org, limit, offset);

    send(res, 200, { events: rows, limit, offset });
  });
}
