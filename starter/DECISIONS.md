# Engineering Decisions

## 1. Database-driven authorization

**What I chose:** Resolve roles and permissions from the database at runtime rather than hardcoding the documented role matrix.

**Why:** The seed and personalisation data contain additional roles and permissions, including a `reviewer` role and `device:reboot`. This demonstrates that the database is the runtime authority for authorization. The permission resolver therefore loads the permission catalogue and role baseline from the database.

**What I rejected:** A frontend or backend constant containing the complete role-to-permission matrix. That would work for the initial fixture but would break when the database contains additional roles or permissions.

**What would change my mind:** A schema-level constraint proving that the role and permission relationships are static and cannot change at runtime.

---

## 2. Explicit deny precedence

**What I chose:** Explicit denies override allows.

**Why:** Permission resolution evaluates explicit deny grants before baseline and grant allows. This allows an organisation-wide deny to remove a permission that the caller would otherwise receive from their role.

**What I rejected:** A "most specific grant wins" rule as the general authorization strategy. The required behaviour is deterministic deny-wins resolution.

**What would change my mind:** A database rule or test fixture demonstrating that a narrower allow must explicitly override an organisation-wide deny.

---

## 3. Permission resolution is server-side

**What I chose:** Keep the complete authorization decision on the server and expose resolved permissions to the frontend.

**Why:** The server is the enforcement point and the database is the runtime source of authorization truth. The frontend should consume the server's answer rather than reconstruct the authorization policy.

**What I rejected:** Reimplementing the role and grant matrix inside React.

**What would change my mind:** A dedicated client authorization service provided by the platform that uses exactly the same server-side policy source.

---

## 4. Invisible devices return 404

**What I chose:** A device that the caller cannot view is treated as invisible rather than returning a redacted resource.

**Why:** The brief requires invisible resources to return `404`. The device list therefore includes only devices for which the caller has resolved `device:view`, and direct device access applies the same authorization decision.

**What I rejected:** Returning a device with sensitive fields removed or returning `403` for a device the caller cannot see.

**What would change my mind:** A product requirement that users must be able to distinguish between an inaccessible device and a nonexistent device.

---

## 5. Device permissions are resolved in batches

**What I chose:** Resolve permissions for device lists in a batched operation rather than querying authorization independently for every device.

**Why:** The device list needs the caller's resolved permissions for each visible device. Resolving those permissions in one database operation avoids an N+1 query pattern and keeps authorization logic centralized.

**What I rejected:** Performing separate permission-resolution database queries for every device row.

**What would change my mind:** A very small fixed device set where the performance and query complexity trade-off was demonstrated to be irrelevant.

---

## 6. Session creation requires two permissions

**What I chose:** Require both `session:start` and the permission corresponding to the requested session mode.

**Why:** Starting a session is an independent capability from accessing a device. A caller may have permission to view or control a device without being allowed to start a session.

The mode permissions are:

- `view` → `device:view`
- `control` → `device:control`
- `terminal` → `device:terminal`

The two checks also allow the API to distinguish a missing general session permission from a missing device-specific permission.

**What I rejected:** Treating `device:control` or another device permission as automatically granting `session:start`.

**What would change my mind:** A schema-level rule explicitly making session creation part of every device permission.

---

## 7. Session authority is snapshotted

**What I chose:** Store the relevant authorization information when a session starts.

**Why:** A session represents a control-plane record of an authorization decision made at creation time. Capturing the role/grant authority and snapshot time makes the session auditable and prevents the historical record from depending entirely on later permission changes.

**What I rejected:** Reconstructing the complete historical authorization decision only from the caller's current role and grants.

**What would change my mind:** A requirement that existing sessions must always dynamically inherit every later permission change.

---

## 8. Refresh tokens remain HttpOnly

**What I chose:** Keep refresh tokens in an HttpOnly cookie and keep the access token in memory only.

**Why:** The browser can automatically send the refresh cookie while JavaScript cannot read it. The UI tests also verify that authentication tokens are not persisted in localStorage or sessionStorage.

The frontend restores the access token after a page reload by calling the refresh endpoint with `POST /v1/auth/refresh`.

**What I rejected:** Persisting access or refresh tokens in web storage simply to make reload handling easier.

**What would change my mind:** A platform requirement that browser JavaScript must directly access the refresh credential.

---

## 9. Authentication failures do not reveal account existence

**What I chose:** Use the same user-facing authentication failure reason for incorrect credentials and nonexistent accounts.

**Why:** The login flow should not allow an unauthenticated caller to distinguish whether an email address exists in the system.

**What I rejected:** Returning different messages such as "account not found" and "incorrect password".

**What would change my mind:** A verified product requirement that account discovery is intentionally part of the login experience.

---

## 10. Organisation context is enforced on the server

**What I chose:** Treat the authenticated organisation membership and server-issued access-token context as authorization inputs rather than trusting a client-selected organisation.

**Why:** The application supports multiple organisations per user. Switching organisations must change the server authorization context, not merely change the UI.

The server validates the caller's membership in the requested organisation and prevents resources from another organisation from being accessed through an organisation-scoped route.

**What I rejected:** Allowing the browser to choose an organisation ID and using that value directly for authorization.

**What would change my mind:** A server-side architecture where organisation identity is derived from a trusted gateway rather than from the application request.

---

## 11. Organisation-specific UI state comes from the active server context

**What I chose:** Render the active organisation, role, theme, navigation, devices, members, grants, sessions, and audit data from the currently authenticated organisation context.

**Why:** This prevents stale UI state from one organisation from appearing after switching to another organisation. It also makes the active organisation visibly identifiable.

**What I rejected:** Keeping independent client-side copies of organisation authorization state and switching between them without asking the server for a new token/context.

**What would change my mind:** A server-provided immutable organization context that could safely be cached for the entire browser session.

---

## 12. Permission-controlled UI uses presence rather than disabled controls

**What I chose:** A permission-controlled element is either present with its permission metadata and an unlocked state, or absent.

**Why:** The brief explicitly requires permission-controlled elements to be represented through presence rather than a disabled state. Hiding a control is only a presentation decision; the corresponding API remains protected by server-side authorization.

**What I rejected:** Rendering unauthorized buttons as disabled controls.

**What would change my mind:** A product requirement that users should be able to discover unavailable actions through disabled controls.

---

## 13. Audit denied operations as well as successful mutations

**What I chose:** Record security-relevant successful actions and denied authorization attempts.

**Why:** A control plane needs an attributable record of important actions and failed authorization attempts. Recording request IDs, actor, organisation, action, and result provides useful audit context.

**What I rejected:** Auditing only successful mutations.

**What would change my mind:** A documented requirement limiting the audit stream to successful operations only.

---

## 14. Audit access is separately permission-controlled

**What I chose:** Protect audit retrieval with the `audit:read` permission.

**Why:** Audit records can contain security-sensitive information and should not automatically be visible to every organisation member.

**What I rejected:** Allowing every authenticated organisation member to read the complete audit history.

**What would change my mind:** An organisation-wide requirement that audit history is intentionally public to all members.

---

## 15. Windows-compatible filesystem handling

**What I chose:** Use `fileURLToPath()` when converting module-relative file URLs into filesystem paths.

**Why:** During Windows setup, using `.pathname` directly from a file URL produced an invalid path such as `C:\C:\...`. The same issue affected static distribution path handling.

The implementation was changed to use Node's filesystem-aware URL conversion.

**What I rejected:** Manually manipulating the `file:` URL string to remove the extra path prefix.

**What would change my mind:** Moving the application to an environment where module-relative filesystem paths are never required.

---

## 16. Real remote device control is intentionally not implemented

**What I chose:** Sessions remain control-plane records and do not connect to or control real remote devices.

**Why:** The brief explicitly states that no real remote-access functionality is required. Implementing a remote-control transport would add significant scope without contributing to the required authorization and control-plane behaviour.

**What I rejected:** Building a real remote desktop, terminal transport, or device-control channel.

**What would change my mind:** A product requirement and integration contract for a real remote-access provider.

---

## 17. The frontend does not duplicate the authorization engine

**What I chose:** The frontend consumes server-resolved permission results and uses them to determine what should be rendered.

**Why:** The server must remain the source of enforcement. Duplicating permission precedence, grant scope, validity windows, and role logic in React would create two authorization implementations that could drift apart.

**What I rejected:** A client-side function such as `isOwner()`, `isAdmin()`, or a hardcoded role-permission map as the source of UI authorization.

**What would change my mind:** A shared authorization package used identically by both the server and frontend, backed by the same runtime policy source.

---

## 18. Schema is the source of truth

**What I chose:** Treat the database schema and runtime database data as authoritative when written documentation and the runtime model disagree.

**Why:** The brief explicitly identifies the schema as ground truth. The implementation therefore follows the actual database relationships, permission catalogue, role definitions, grants, and organisation configuration rather than assuming that the documented role matrix is exhaustive.

The personalisation fixture was particularly useful because it introduced additional role and permission data that a hardcoded implementation would not naturally support.

**What I rejected:** Silently choosing whichever interpretation was easier to implement or treating the documented role matrix as the complete authorization model.

**What would change my mind:** An explicit task requirement stating that a particular documented rule overrides the database schema.

---

# Where this repo argues with itself

The main potential source of disagreement was between the written role/permission examples and the dynamic runtime data.

The implementation follows the database/schema as the runtime source of authorization truth. The permission resolver does not assume that the documented roles are the complete set of possible roles or that the documented permissions are the complete catalogue.

The personalisation checks were used as evidence for this decision because they introduce additional authorization data beyond the basic seeded examples.

This means the console can consume server-resolved permissions without knowing the complete role matrix in advance.

---

# Deliberately not built

## Real remote device access

Real remote desktop, terminal transport, or device-control functionality was not implemented because the brief explicitly requires a control plane rather than actual remote access.

Sessions therefore represent authorization and lifecycle records only.

## Client-side authorization engine

A second authorization engine was not built in React. The frontend consumes the server's resolved permissions instead.

This avoids duplicating:

- role baselines;
- permission catalogue rules;
- grant scope;
- explicit deny precedence;
- grant validity;
- device-specific authorization.

## Persistent access-token storage

Access tokens are kept in memory rather than localStorage or sessionStorage. Reload recovery uses the HttpOnly refresh cookie.

## Unnecessary product functionality

The implementation focuses on the required control-plane workflows: authentication, organisation context, members, devices, grants, sessions, audit, and the permission-driven console.

Features unrelated to the authorization control plane were deliberately kept outside the scope of the implementation.
