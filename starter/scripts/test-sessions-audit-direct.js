import { spawn, execFileSync } from 'node:child_process';
import { rmSync, existsSync } from 'node:fs';

const PORT = 8124;
const BASE = `http://localhost:${PORT}/v1`;
const DB = 'test-sessions-audit.db';

for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) rmSync(DB + s);
execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB }, stdio: 'ignore' });

const server = spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, DATABASE_FILE: DB, PORT: String(PORT), NODE_ENV: 'production', JWT_SECRET: 'test-secret' },
  stdio: ['ignore', 'ignore', 'inherit'],
});

await new Promise((r) => setTimeout(r, 1200));

let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(56)}${ok ? '' : ` got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};

async function call(method, path, { token, body } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body) headers['content-type'] = 'application/json';

  const res = await fetch(BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
  return { status: res.status, body: json, raw: text };
}

const login = async (email, orgId = null, password = 'demo1234') => {
  const res = await call('POST', '/auth/login', { body: { email, password, ...(orgId ? { orgId } : {}) } });
  return res.body?.token;
};

try {
  const danaAcme = await login('dana@example.test', 'org_acme');
  const samAcme = await login('sam@example.test', 'org_acme');
  const samGlobex = await login('sam@example.test', 'org_globex');
  const viewerAcme = await login('viewer@acme.test', 'org_acme');

  console.log('\n== SESSIONS: POST /v1/orgs/:org/sessions ==');
  // invalid mode
  const invMode = await call('POST', '/orgs/org_acme/sessions', { token: samAcme, body: { deviceId: 'dev_lab_win_01', mode: 'invalid' } });
  check('invalid mode returns 400', invMode.status, 400);

  // device not found
  const notFoundDev = await call('POST', '/orgs/org_acme/sessions', { token: samAcme, body: { deviceId: 'dev_nonexistent', mode: 'control' } });
  check('unknown device returns 404', notFoundDev.status, 404);

  // cross-org device
  const crossDev = await call('POST', '/orgs/org_acme/sessions', { token: samAcme, body: { deviceId: 'dev_globex_desk_01', mode: 'control' } });
  check('cross-org device returns 404', crossDev.status, 404);

  // start view session
  const view1 = await call('POST', '/orgs/org_acme/sessions', { token: samAcme, body: { deviceId: 'dev_lab_win_01', mode: 'view' } });
  check('start view session -> 201', view1.status, 201);
  check('  state is active', view1.body.state, 'active');
  const view1Id = view1.body.id;

  // concurrent view session on same device
  const view2 = await call('POST', '/orgs/org_acme/sessions', { token: samAcme, body: { deviceId: 'dev_lab_win_01', mode: 'view' } });
  check('start concurrent view session -> 201', view2.status, 201);

  // control session
  const ctrl1 = await call('POST', '/orgs/org_acme/sessions', { token: samAcme, body: { deviceId: 'dev_lab_win_01', mode: 'control' } });
  check('start control session -> 201', ctrl1.status, 201);
  const ctrl1Id = ctrl1.body.id;

  // duplicate control session -> 409 DEVICE_BUSY
  const ctrl2 = await call('POST', '/orgs/org_acme/sessions', { token: danaAcme, body: { deviceId: 'dev_lab_win_01', mode: 'control' } });
  check('duplicate control session -> 409', ctrl2.status, 409);
  check('  error code DEVICE_BUSY', ctrl2.body.error.code, 'DEVICE_BUSY');

  console.log('\n== SESSIONS: GET /v1/orgs/:org/sessions ==');
  const list = await call('GET', '/orgs/org_acme/sessions', { token: samAcme });
  check('list sessions -> 200', list.status, 200);
  check('  contains created sessions', list.body.sessions.some(s => s.id === ctrl1Id), true);

  console.log('\n== SESSIONS: GET /v1/sessions/:id ==');
  // own session
  const getOwn = await call('GET', `/sessions/${ctrl1Id}`, { token: samAcme });
  check('get own session -> 200', getOwn.status, 200);
  check('  mode is control', getOwn.body.mode, 'control');
  check('  authorized_by is present', Boolean(getOwn.body.authorized_by), true);

  // other user's session with session:view
  const getOther = await call('GET', `/sessions/${ctrl1Id}`, { token: danaAcme });
  check('get other session (with session:view) -> 200', getOther.status, 200);

  // cross org session access
  const getCross = await call('GET', `/sessions/${ctrl1Id}`, { token: samGlobex });
  check('cross-org session get -> 404', getCross.status, 404);

  console.log('\n== SESSIONS: DELETE /v1/sessions/:id ==');
  // own session delete (user_stopped)
  const delOwn = await call('DELETE', `/sessions/${view1Id}`, { token: samAcme });
  check('delete own session -> 204', delOwn.status, 204);

  const getEnded = await call('GET', `/sessions/${view1Id}`, { token: samAcme });
  check('  state is ended', getEnded.body.state, 'ended');
  check('  end_reason is user_stopped', getEnded.body.end_reason, 'user_stopped');

  // delete already ended -> 409
  const delEndedAgain = await call('DELETE', `/sessions/${view1Id}`, { token: samAcme });
  check('delete already ended -> 409', delEndedAgain.status, 409);

  // admin terminate (admin_terminated)
  const adminTerm = await call('DELETE', `/sessions/${ctrl1Id}`, { token: danaAcme });
  check('admin terminate other session -> 204', adminTerm.status, 204);

  const getAdminTerm = await call('GET', `/sessions/${ctrl1Id}`, { token: danaAcme });
  check('  end_reason is admin_terminated', getAdminTerm.body.end_reason, 'admin_terminated');

  console.log('\n== AUDIT: GET /v1/orgs/:org/audit ==');
  // operator in Acme without audit:read -> 403
  const opAudit = await call('GET', '/orgs/org_acme/audit', { token: samAcme });
  check('operator without audit:read -> 403', opAudit.status, 403);

  // auditor in Globex with audit:read -> 200
  const audAudit = await call('GET', '/orgs/org_globex/audit', { token: samGlobex });
  check('auditor with audit:read -> 200', audAudit.status, 200);
  check('  events returned as array', Array.isArray(audAudit.body.events), true);

  // owner in Acme with audit:read -> 200
  const ownerAudit = await call('GET', '/orgs/org_acme/audit', { token: danaAcme });
  check('owner audit -> 200', ownerAudit.status, 200);
  check('  contains session events', ownerAudit.body.events.some(e => e.action === 'session.start'), true);

  // pagination bounds
  check('limit=0 -> 400', (await call('GET', '/orgs/org_acme/audit?limit=0', { token: danaAcme })).status, 400);
  check('limit=-5 -> 400', (await call('GET', '/orgs/org_acme/audit?limit=-5', { token: danaAcme })).status, 400);
  check('limit=201 -> 400', (await call('GET', '/orgs/org_acme/audit?limit=201', { token: danaAcme })).status, 400);
  check('limit=200 -> 200', (await call('GET', '/orgs/org_acme/audit?limit=200', { token: danaAcme })).status, 200);
  check('offset=-1 -> 400', (await call('GET', '/orgs/org_acme/audit?offset=-1', { token: danaAcme })).status, 400);
  check('offset=10 -> 200', (await call('GET', '/orgs/org_acme/audit?offset=10', { token: danaAcme })).status, 200);

  console.log(`\n${fail === 0 ? 'ALL SESSIONS & AUDIT TESTS PASSED' : 'FAILURES OCCURRED'} — ${pass} passed, ${fail} failed\n`);
} finally {
  server.kill();
  for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) rmSync(DB + s);
}
