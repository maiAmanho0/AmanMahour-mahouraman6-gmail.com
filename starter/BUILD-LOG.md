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

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
