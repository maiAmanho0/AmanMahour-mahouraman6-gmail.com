# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

## 2026-09-26 · Phase 0 — orientation

Set up the environment with Node.js v22.20.0 and npm 10.9.3, installing 106 packages with 0 vulnerabilities.
Running `npm run db:reset` failed on Windows because the script relied on Unix `rm -f`; removed `app.db*` files via PowerShell.
`npm run db:load` subsequently threw ENOENT (`C:\C:\...`) because `scripts/load-db.js` used `.pathname` on a file URL.
Fixed `here` to pass the `URL` object directly to `readFileSync`, allowing `npm run db:load` to succeed.
Observed seeded counts: 3 orgs, 8 users, 10 memberships, 9 devices, 6 grants, 3 sessions, 7 audit events, 20 permissions, 27 patterns.
Discovered dynamic personalisation: added extra org "Ironside Labs", extra role "reviewer", and extra permission "device:reboot" (allowed on `dev_p_bb3398_a`, denied on `dev_p_bb3398_b`), reinforcing that roles and permissions must be dynamically resolved from the database.

## 2026-09-26 · Phase 1 — token verification

`verifyAccessToken` in `server/auth.js` started as an unimplemented stub throwing `NOT_IMPLEMENTED`.
Implemented strict JWT verification using existing helpers: requiring 3 dot-separated segments, valid base64url JSON header and payload, strict `alg: 'HS256'` and `typ: 'JWT'` checks, constant-time HMAC-SHA256 signature verification via `timingSafeEqual`, half-open expiry validation (`exp > nowSec()`), `iss`/`aud` matching constants, and non-empty `jti`.
Ensured all malformed tokens, algorithm substitutions, signature mismatches, and expired tokens throw `unauthenticated(...)` returning 401 UNAUTHENTICATED.
Ran `node scripts/check-jwt.js`: all 43 test cases passed cleanly (43 passed, 0 failed).

## Phase 2 · caller context and the resolution engine

Started with the assumption that the role name in the JWT could be treated as the authorization answer. The seeded data and personalisation fixture showed that this is insufficient: permissions can be changed through database grants and can be scoped to a device.

The final model is:
1. verify the access token;
2. resolve the caller's membership in the requested organisation;
3. load the permission catalogue and role baseline from the database;
4. evaluate active, non-revoked grants for the caller and organisation;
5. apply explicit denies before allows;
6. return a resolved permission object with `effect`, `source`, and `reason`.

The resolver also batches device permission resolution so the device list does not perform a permission query for every individual device.

Validation:
- `node scripts/check-jwt.js` → 43 passed
- `node scripts/check-permissions.js` → 35 passed
- `npm run personalisation` → 18 passed
- `node scripts/check-api.js` → 66 passed

## Phase 3 · orgs, members, invites

Implemented organisation, membership, invitation, and effective-permission routes.

Organisation membership is part of the caller context rather than being inferred from a client-supplied organisation alone. Cross-organisation access is rejected at the server boundary.

Invitations use an explicit lifecycle:
- an administrator creates the invitation;
- the token exposes only the information required to redeem it;
- accepting the invitation creates the membership and user when appropriate;
- invalid or unusable invitation tokens are rejected without exposing organisation details.

The console changes its active organisation through the server-issued token rather than treating the browser's selected organisation as an authorization decision.

## Phase 4 · devices and grants

Device visibility is permission-controlled. A caller who cannot `device:view` a device does not receive a redacted device row; the resource is treated as invisible and returns 404 for direct access.

For conflicting grants, explicit deny wins over an allow. Grants are filtered by organisation, user, validity window, revocation state, and device scope before resolution.

The frontend consumes the server-resolved permissions instead of rebuilding the role matrix in React. The database permission catalogue and role definitions remain the runtime authority.

## Phase 5 · sessions

Session creation requires two separate permissions:
- `session:start`
- the requested device mode permission (`device:view`, `device:control`, or `device:terminal`).

These are checked in order so the API can distinguish a missing session-start permission from a missing device permission.

Active session authority is snapshotted when a session starts. Session expiry is derived from the organisation's configured maximum session duration. Exclusive-control conflicts return a distinct `DEVICE_BUSY` response.

## Phase 6 · audit

Auditable events include authentication activity, permission-sensitive mutations, device lifecycle operations, membership/invitation changes, grants, and session lifecycle actions.

Denied operations are also recorded with the relevant actor, organisation, request ID, action, and result so an authorization failure is attributable rather than silently disappearing.

The audit API is separately permission-gated with `audit:read`.

## Phase 7 · the console

The initial console implementation used presentation-level role assumptions. The final implementation instead consumes the server's resolved permissions for the active organisation.

The important UI rule is presence rather than disabled-state rendering: permission-controlled controls are either rendered with `data-permission` and `data-state="unlocked"` or are absent.

The active organisation is visually identifiable through its organisation-specific theme. Switching organisations changes both the server context and the rendered shell, and the application does not persist the access token in web storage.

The console was validated against all 25 provided Playwright UI tests.
## Phase 8 · hardening

Windows-specific setup issues were fixed in the database loader because the original file URL handling produced `C:\C:\...` paths. The Unix-specific database reset command was also handled during local setup.

The production static-server path was corrected to use `fileURLToPath(...)` so Windows paths resolve correctly when serving `dist/index.html`.

Refresh-session restoration was tested through a real browser reload. The frontend initially called `/auth/refresh` with GET while the API requires POST; this was corrected so the refresh cookie restores the access token after reload.

Final validation:
- `npm run build` → passed
- `npx playwright test` → 25 passed, 0 failed

The project intentionally does not implement real remote device access. Sessions represent control-plane records only, as required by the brief.

## Open threads

The implementation is complete against the provided automated suite. With additional time, I would add more focused automated coverage around invitation edge cases, concurrent session creation, and additional dynamic permission catalogue changes.