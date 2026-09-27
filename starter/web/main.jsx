import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';

const API = '/v1';
let accessToken = null;

const ORG_THEMES = {
  cobalt: { accent: '#2563eb', soft: '#eff6ff', header: '#1e3a8a' },
  emerald: { accent: '#059669', soft: '#ecfdf5', header: '#065f46' },
  violet: { accent: '#7c3aed', soft: '#f5f3ff', header: '#4c1d95' },
  amber: { accent: '#d97706', soft: '#fffbeb', header: '#92400e' },
};

const GRANT_PERMISSIONS = [
  'device:view',
  'device:control',
  'device:terminal',
  'device:provision',
  'device:update',
  'device:list',
  'user:read',
  'user:invite',
  'user:remove',
  'user:role:update',
  'session:start',
  'session:view',
  'session:terminate',
  'audit:read',
  'org:update',
  'org:delete',
];

function themeFor(org) {
  return ORG_THEMES[org?.theme] || ORG_THEMES.cobalt;
}

async function api(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;

  const response = await fetch(`${API}${path}`, {
    ...options,
    headers,
    credentials: 'include',
  });

  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    const error = data?.error || {};
    const err = new Error(
      error.message || `Request failed with status ${response.status}`,
    );
    err.code = error.code;
    err.reason = error.reason;
    err.requestId = error.requestId;
    err.status = response.status;
    throw err;
  }

  return data;
}

function readableError(error) {
  if (!error) return 'Something went wrong.';
  if (error.reason === 'missing_permission') {
    return 'You do not have the required permission for this action.';
  }
  if (error.reason === 'missing_device_permission') {
    return 'You do not have the required permission on this device.';
  }
  if (error.reason === 'explicit_deny') {
    return 'This action is explicitly denied.';
  }
  if (error.reason === 'implicit') {
    return 'No permission has been granted for this action.';
  }
  if (error.code === 'NOT_FOUND') return 'The requested resource was not found.';
  if (error.code === 'DEVICE_BUSY') return 'This device already has an exclusive session.';
  return error.message || 'Something went wrong.';
}

function PermissionButton({ permission, allowed, children, onClick, testId }) {
  if (!allowed) return null;
  return (
    <button
      type="button"
      data-permission={permission}
      data-state="unlocked"
      data-testid={testId}
      onClick={onClick}
      style={buttonStyle}
    >
      {children}
    </button>
  );
}

function Login({ onLoggedIn }) {
  const [email, setEmail] = useState('dana@example.test');
  const [password, setPassword] = useState('demo1234');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setError('');

    if (!email.trim() || !password) {
      setError('Please enter your email and password.');
      return;
    }

    setLoading(true);
    try {
      const result = await api('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: email.trim(), password }),
      });
      accessToken = result.token;
      const me = await api('/auth/me');
      onLoggedIn(me);
    } catch (err) {
      setError(readableError(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main style={loginPage}>
      <form data-testid="login-form" onSubmit={submit} style={loginCard}>
        <div style={eyebrow}>REMOTE ACCESS CONTROL</div>
        <h1 style={{ margin: '14px 0 6px' }}>RemoteOps</h1>
        <p style={{ margin: '0 0 26px', color: '#64748b' }}>
          Sign in to manage your organization.
        </p>

        <label htmlFor="login-email">Email</label>
        <input
          id="login-email"
          data-testid="login-email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          autoComplete="username"
          style={inputStyle}
        />

        <label htmlFor="login-password">Password</label>
        <input
          id="login-password"
          data-testid="login-password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
          style={inputStyle}
        />

        {error && (
          <div data-testid="login-error" role="alert" style={errorBox}>
            {error}
          </div>
        )}

        <button type="submit" data-testid="login-submit" style={primaryButton}>
          {loading ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  );
}

function InviteView() {
  const token = decodeURIComponent(window.location.pathname.split('/').pop() || '');
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [accepted, setAccepted] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    api(`/invites/${encodeURIComponent(token)}`)
      .then((data) => {
        if (alive) setInvite(data);
      })
      .catch((err) => {
        if (alive) setError(readableError(err));
      })
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [token]);

  if (accepted) {
    return <Login onLoggedIn={() => { window.location.href = '/'; }} />;
  }

  if (loading) return <main style={centerPage}>Loading invitation…</main>;

  if (error || !invite) {
    return (
      <main style={loginPage}>
        <section style={loginCard}>
          <div style={eyebrow}>INVITATION</div>
          <h1>Invitation unavailable</h1>
          <div data-testid="invite-error" role="alert" style={errorBox}>
            {error || 'This invitation is no longer available.'}
          </div>
        </section>
      </main>
    );
  }

  async function acceptInvite(event) {
    event.preventDefault();
    setError('');
    try {
      await api(`/invites/${encodeURIComponent(token)}/accept`, {
        method: 'POST',
        body: JSON.stringify({ name: name.trim(), password }),
      });
      setAccepted(true);
    } catch (err) {
      setError(readableError(err));
    }
  }

  return (
    <main style={loginPage}>
      <form onSubmit={acceptInvite} style={loginCard}>
        <div style={eyebrow}>REMOTE ACCESS INVITATION</div>
        <h1>Join RemoteOps</h1>

        <label>Organization</label>
        <input value={invite.orgName || ''} readOnly style={inputStyle} />

        <label>Role</label>
        <div data-testid="invite-role" style={inputStyle}>
          {invite.role || ''}
        </div>

        <label>Email</label>
        <input data-testid="invite-email" value={invite.email || ''} readOnly style={inputStyle} />

        <label>Name</label>
        <input
          data-testid="invite-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          style={inputStyle}
        />

        <label>Password</label>
        <input
          data-testid="invite-password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={inputStyle}
        />

        {error && <div data-testid="invite-error" role="alert" style={errorBox}>{error}</div>}

        <button data-testid="invite-submit" type="submit" style={primaryButton}>
          Accept invitation
        </button>
      </form>
    </main>
  );
}

function App() {
  const inviteRoute = window.location.pathname.startsWith('/invite/');
  if (inviteRoute) return <InviteView />;

  const [me, setMe] = useState(null);
  const [loading, setLoading] = useState(true);
  const [globalError, setGlobalError] = useState('');

  useEffect(() => {
    restoreSession();
  }, []);

  async function restoreSession() {
    try {
      console.log('RESTORE: calling refresh');

      const refreshed = await api('/auth/refresh', {
        method: 'POST',
      });
      console.log('RESTORE: refresh succeeded');

      accessToken = refreshed.token;

      const currentUser = await api('/auth/me');
      console.log('RESTORE: me succeeded', currentUser);

      setMe(currentUser);
    } catch (err) {
      console.error('RESTORE FAILED:', err);
      accessToken = null;
      setMe(null);
    } finally {
      setLoading(false);
    }
  }

  async function switchOrganization(orgId) {
    setGlobalError('');
    try {
      const result = await api('/auth/token', {
        method: 'POST',
        body: JSON.stringify({ orgId }),
      });
      accessToken = result.token;
      const currentUser = await api('/auth/me');
      setMe(currentUser);
    } catch (err) {
      setGlobalError(readableError(err));
    }
  }

  function logout() {
    accessToken = null;
    setMe(null);
  }

  if (loading) return <main style={centerPage}>Loading RemoteOps…</main>;
  if (!me) return <Login onLoggedIn={setMe} />;

  return (
    <Console
      me={me}
      setMe={setMe}
      onSwitchOrg={switchOrganization}
      onLogout={logout}
      globalError={globalError}
      setGlobalError={setGlobalError}
    />
  );
}

function Console({
  me,
  setMe,
  onSwitchOrg,
  onLogout,
  globalError,
  setGlobalError,
}) {
  const [view, setView] = useState('devices');
  const org = me.org;
  const theme = themeFor(org);
  const permissions = me.permissions || {};

  const can = (permission) => permissions[permission]?.effect === 'allow';

  const navItems = useMemo(
    () => [
      { id: 'devices', label: 'Devices', permission: 'device:list' },
      { id: 'people', label: 'People', permission: 'user:read' },
      { id: 'grants', label: 'Grants', permission: 'user:read' },
      { id: 'sessions', label: 'Sessions', permission: 'session:view' },
      { id: 'audit', label: 'Audit', permission: 'audit:read' },
      { id: 'admin', label: 'Admin', permission: 'org:update' },
    ],
    [],
  );

  const visibleNav = navItems.filter((item) => can(item.permission));

  useEffect(() => {
    if (!visibleNav.some((item) => item.id === view)) {
      setView(visibleNav[0]?.id || 'devices');
    }
  }, [me, view]);

  async function createOrg() {
    const name = window.prompt('Organization name');
    if (!name?.trim()) return;

    setGlobalError('');
    try {
      const created = await api('/orgs', {
        method: 'POST',
        body: JSON.stringify({ name: name.trim() }),
      });
      await onSwitchOrg(created.id);
      setView('devices');
    } catch (err) {
      setGlobalError(readableError(err));
    }
  }

  return (
    <div
      data-testid="app-shell"
      data-org-id={org.id}
      data-org-theme={org.theme}
      style={{
        minHeight: '100vh',
        background: theme.soft,
        color: '#111827',
        fontFamily: 'Inter, ui-sans-serif, system-ui, sans-serif',
      }}
    >
      <header
        style={{
          background: theme.header,
          color: '#fff',
          padding: '18px 28px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 20,
        }}
      >
        <div>
          <div style={{ fontSize: 12, opacity: 0.75 }}>REMOTEOPS CONTROL PLANE</div>
          <div style={{ fontSize: 23, fontWeight: 800, marginTop: 3 }}>
            {org.name}
          </div>
        </div>

        <div style={{ textAlign: 'right' }}>
          <div style={{ fontWeight: 700 }}>{me.user.name}</div>
          <div data-testid="active-role" style={{ fontSize: 13, opacity: 0.8 }}>
            {me.role}
          </div>
          <div style={{ fontSize: 12, opacity: 0.65 }}>{me.user.email}</div>
        </div>
      </header>

      <div style={{ display: 'flex', minHeight: 'calc(100vh - 82px)' }}>
        <aside
          style={{
            width: 250,
            flexShrink: 0,
            background: '#fff',
            borderRight: '1px solid #e2e8f0',
            padding: 18,
          }}
        >
          <div style={sectionLabel}>ORGANIZATION</div>

          <div style={{ display: 'grid', gap: 6, marginBottom: 16 }}>
            {me.orgs.map((item) => {
              const active = item.id === org.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  data-testid="org-option"
                  data-org-id={item.id}
                  onClick={() => onSwitchOrg(item.id)}
                  style={{
                    width: '100%',
                    textAlign: 'left',
                    padding: '10px 12px',
                    borderRadius: 8,
                    border: active ? `2px solid ${theme.accent}` : '1px solid #cbd5e1',
                    background: active ? theme.soft : '#fff',
                    color: '#1e293b',
                    fontWeight: active ? 700 : 500,
                    cursor: 'pointer',
                  }}
                >
                  <div>{item.name}</div>
                  <div style={{ fontSize: 12, marginTop: 3, color: '#64748b' }}>
                    {item.role}
                  </div>
                </button>
              );
            })}
          </div>

          <button
            type="button"
            data-testid="create-org"
            onClick={createOrg}
            style={{
              width: '100%',
              marginBottom: 24,
              padding: '9px 12px',
              borderRadius: 8,
              border: `1px solid ${theme.accent}`,
              background: '#fff',
              color: theme.accent,
              fontWeight: 700,
              cursor: 'pointer',
            }}
          >
            + Create organization
          </button>

          <div style={sectionLabel}>CONSOLE</div>
          <nav style={{ display: 'grid', gap: 5 }}>
            {visibleNav.map((item) => (
              <button
                key={item.id}
                type="button"
                data-testid={`nav-${item.id}`}
                onClick={() => setView(item.id)}
                style={{
                  textAlign: 'left',
                  border: 0,
                  borderRadius: 8,
                  padding: '10px 12px',
                  background: view === item.id ? theme.soft : 'transparent',
                  color: view === item.id ? theme.accent : '#475569',
                  fontWeight: view === item.id ? 700 : 500,
                  cursor: 'pointer',
                }}
              >
                {item.label}
              </button>
            ))}
          </nav>

          <div style={{ marginTop: 30, paddingTop: 18, borderTop: '1px solid #e2e8f0' }}>
            <button type="button" onClick={onLogout} style={secondaryButton}>
              Sign out
            </button>
          </div>
        </aside>

        <main style={{ flex: 1, padding: 28, minWidth: 0 }}>
          {globalError && (
            <div role="alert" style={errorBox}>
              {globalError}
            </div>
          )}

          {view === 'devices' && (
            <DevicesView orgId={org.id} can={can} theme={theme} />
          )}

          {view === 'people' && (
            <PeopleView
              orgId={org.id}
              can={can}
              theme={theme}
              onRefresh={async () => setMe(await api('/auth/me'))}
            />
          )}

          {view === 'grants' && (
            <GrantsView orgId={org.id} can={can} theme={theme} />
          )}

          {view === 'sessions' && (
            <SessionsView orgId={org.id} can={can} theme={theme} />
          )}

          {view === 'audit' && <AuditView orgId={org.id} theme={theme} />}

          {view === 'admin' && (
            <AdminView
              org={org}
              can={can}
              theme={theme}
              onUpdated={async () => setMe(await api('/auth/me'))}
            />
          )}
        </main>
      </div>
    </div>
  );
}

function DevicesView({ orgId, can, theme }) {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError('');

    api(`/orgs/${encodeURIComponent(orgId)}/devices`)
      .then((result) => alive && setDevices(result.devices || []))
      .catch((err) => alive && setError(readableError(err)))
      .finally(() => alive && setLoading(false));

    return () => { alive = false; };
  }, [orgId]);

  if (loading) {
    return (
      <section>
        <h1 style={{ marginTop: 0 }}>Devices</h1>
        <p style={{ color: '#64748b' }}>Loading devices…</p>
      </section>
    );
  }

  return (
    <section>
      <div style={pageHeader}>
        <div>
          <h1 style={{ margin: 0 }}>Devices</h1>
          <p style={{ color: '#64748b', margin: '7px 0 0' }}>
            Remote endpoints visible in this organization.
          </p>
        </div>
        <PermissionButton
          permission="device:provision"
          allowed={can('device:provision')}
          onClick={() => { }}
        >
          Add device
        </PermissionButton>
      </div>

      {error && <div role="alert" style={errorBox}>{error}</div>}

      {devices.length === 0 ? (
        <div data-testid="devices-empty" style={emptyBox}>
          No visible devices in this organization.
        </div>
      ) : (
        <div style={tableCard}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#f8fafc' }}>
                <th style={th}>Device</th>
                <th style={th}>Type</th>
                <th style={th}>Status</th>
                <th style={th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((device) => {
                const devicePermissions = device.permissions || {};
                const canControl =
                  devicePermissions['device:control']?.effect === 'allow';
                const canTerminal =
                  devicePermissions['device:terminal']?.effect === 'allow';

                return (
                  <tr
                    key={device.id}
                    data-testid="device-row"
                    data-device-id={device.id}
                    style={{ borderTop: '1px solid #e2e8f0' }}
                  >
                    <td style={td}>
                      <div style={{ fontWeight: 700 }}>{device.name}</div>
                      <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 3 }}>
                        {device.id}
                      </div>
                    </td>
                    <td style={td}>{device.kind}</td>
                    <td style={td}>
                      <span
                        style={{
                          display: 'inline-flex',
                          padding: '5px 9px',
                          borderRadius: 999,
                          background: device.online ? '#ecfdf5' : '#f1f5f9',
                          color: device.online ? '#047857' : '#64748b',
                          fontSize: 12,
                          fontWeight: 700,
                        }}
                      >
                        {device.online ? 'Online' : 'Offline'}
                      </span>
                    </td>
                    <td style={td}>
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        <PermissionButton
                          permission="device:control"
                          allowed={canControl}
                          onClick={() => { }}
                        >
                          Control
                        </PermissionButton>
                        <PermissionButton
                          permission="device:terminal"
                          allowed={canTerminal}
                          onClick={() => { }}
                        >
                          Terminal
                        </PermissionButton>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <div style={{ ...infoBox, background: theme.soft }}>
        Device visibility and actions are resolved by the server.
      </div>
    </section>
  );
}

function PeopleView({ orgId, can, theme }) {
  const [members, setMembers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  async function load() {
    setLoading(true);
    setError('');
    try {
      const result = await api(`/orgs/${encodeURIComponent(orgId)}/members`);
      setMembers(result.members || []);
    } catch (err) {
      setError(readableError(err));
      setMembers([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, [orgId]);

  return (
    <section>
      <div style={pageHeader}>
        <div>
          <h1 style={{ margin: 0 }}>People</h1>
          <p style={{ color: '#64748b', margin: '7px 0 0' }}>
            Organization members and their access.
          </p>
        </div>
        <PermissionButton
          permission="user:invite"
          allowed={can('user:invite')}
          onClick={() => window.alert('Use the invite flow from the organization tools.')}
        >
          Invite member
        </PermissionButton>
      </div>

      {error && <div role="alert" style={errorBox}>{error}</div>}

      {loading ? (
        <p>Loading members…</p>
      ) : (
        <div style={tableCard}>
          {members.map((member) => (
            <div
              key={member.id}
              data-testid="user-row"
              style={{
                padding: 16,
                borderBottom: '1px solid #e2e8f0',
                display: 'grid',
                gridTemplateColumns: '1.3fr 1.5fr .7fr .8fr',
                gap: 12,
                alignItems: 'center',
              }}
            >
              <strong>{member.name}</strong>
              <span>{member.email}</span>
              <span>{member.role}</span>
              <span>{member.status}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function GrantsView({ orgId, can, theme }) {
  const [grants, setGrants] = useState([]);
  const [members, setMembers] = useState([]);
  const [devices, setDevices] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [userId, setUserId] = useState('');
  const [deviceId, setDeviceId] = useState('');
  const [effect, setEffect] = useState('allow');
  const [selectedPermissions, setSelectedPermissions] = useState(['device:terminal']);
  const [error, setError] = useState('');

  async function load() {
    setError('');
    try {
      const [grantResult, memberResult, deviceResult] = await Promise.all([
        api(`/orgs/${encodeURIComponent(orgId)}/grants`),
        api(`/orgs/${encodeURIComponent(orgId)}/members`),
        api(`/orgs/${encodeURIComponent(orgId)}/devices`),
      ]);
      setGrants(grantResult.grants || []);
      setMembers(memberResult.members || []);
      setDevices(deviceResult.devices || []);
      if (!userId && memberResult.members?.[0]) setUserId(memberResult.members[0].id);
      if (!deviceId && deviceResult.devices?.[0]) setDeviceId(deviceResult.devices[0].id);
    } catch (err) {
      setError(readableError(err));
    }
  }

  useEffect(() => { load(); }, [orgId]);

  function togglePermission(permission) {
    setSelectedPermissions((current) =>
      current.includes(permission)
        ? current.filter((p) => p !== permission)
        : [...current, permission],
    );
  }

  async function createGrant(event) {
    event.preventDefault();
    setError('');
    try {
      await api(`/orgs/${encodeURIComponent(orgId)}/grants`, {
        method: 'POST',
        body: JSON.stringify({
          userId,
          deviceId: deviceId || null,
          effect,
          permissions: selectedPermissions,
        }),
      });
      setShowForm(false);
      await load();
    } catch (err) {
      setError(readableError(err));
    }
  }

  async function revokeGrant(id) {
    setError('');
    try {
      await api(`/orgs/${encodeURIComponent(orgId)}/grants/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      await load();
    } catch (err) {
      setError(readableError(err));
    }
  }

  return (
    <section>
      <div style={pageHeader}>
        <div>
          <h1 style={{ margin: 0 }}>Grants</h1>
          <p style={{ color: '#64748b', margin: '7px 0 0' }}>
            Explicit permission grants and denies.
          </p>
        </div>

        {can('grant:create') && (
          <button
            type="button"
            data-testid="new-grant"
            data-permission="grant:create"
            data-state="unlocked"
            onClick={() => setShowForm((v) => !v)}
            style={buttonStyle}
          >
            New grant
          </button>
        )}
      </div>

      {error && <div role="alert" style={errorBox}>{error}</div>}

      {showForm && can('grant:create') && (
        <form onSubmit={createGrant} style={formCard}>
          <h3 style={{ marginTop: 0 }}>Create permission grant</h3>

          <label>User</label>
          <select
            data-testid="grant-user"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            style={inputStyle}
          >
            {members.map((member) => (
              <option key={member.id} value={member.id}>
                {member.name} · {member.email}
              </option>
            ))}
          </select>

          <label>Device</label>
          <select
            data-testid="grant-device"
            value={deviceId}
            onChange={(e) => setDeviceId(e.target.value)}
            style={inputStyle}
          >
            <option value="">Organization-wide</option>
            {devices.map((device) => (
              <option key={device.id} value={device.id}>
                {device.name}
              </option>
            ))}
          </select>

          <label>Effect</label>
          <select
            data-testid="grant-effect"
            value={effect}
            onChange={(e) => setEffect(e.target.value)}
            style={inputStyle}
          >
            <option value="allow">allow</option>
            <option value="deny">deny</option>
          </select>

          <div style={{ margin: '8px 0 16px' }}>
            <strong>Permissions</strong>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 8, marginTop: 10 }}>
              {GRANT_PERMISSIONS.map((permission) => (
                <label key={permission} style={{ display: 'flex', gap: 8 }}>
                  <input
                    type="checkbox"
                    data-permission-key={permission}
                    checked={selectedPermissions.includes(permission)}
                    onChange={() => togglePermission(permission)}
                  />
                  {permission}
                </label>
              ))}
            </div>
          </div>

          <button
            type="submit"
            data-testid="grant-submit"
            data-permission="grant:create"
            data-state="unlocked"
            style={primaryButton}
          >
            Create grant
          </button>
        </form>
      )}

      <div style={tableCard}>
        {grants.map((grant) => (
          <div
            key={grant.id}
            data-testid="grant-row"
            data-effect={grant.effect}
            style={{
              padding: 16,
              borderBottom: '1px solid #e2e8f0',
              display: 'grid',
              gap: 8,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
              <strong>{grant.id}</strong>
              <span>{grant.effect}</span>
            </div>
            <div>
              User: {grant.user_id || '—'} · Device: {grant.device_id || 'organization-wide'}
            </div>
            <div>
              Permissions: {(grant.permissions || []).join(', ')}
            </div>
            {can('grant:revoke') && (
              <button
                type="button"
                data-testid="revoke-grant"
                data-permission="grant:revoke"
                data-state="unlocked"
                onClick={() => revokeGrant(grant.id)}
                style={secondaryButton}
              >
                Revoke
              </button>
            )}
          </div>
        ))}
      </div>

      {grants.length === 0 && (
        <div style={{ ...emptyBox, background: theme.soft }}>No grants found.</div>
      )}
    </section>
  );
}

function SessionsView({ orgId, can }) {
  const [sessions, setSessions] = useState([]);
  const [error, setError] = useState('');

  async function load() {
    try {
      const result = await api(`/orgs/${encodeURIComponent(orgId)}/sessions`);
      setSessions(result.sessions || []);
    } catch (err) {
      setError(readableError(err));
      setSessions([]);
    }
  }

  useEffect(() => { load(); }, [orgId]);

  async function stopSession(id) {
    try {
      await api(`/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' });
      await load();
    } catch (err) {
      setError(readableError(err));
    }
  }

  return (
    <section>
      <h1 style={{ marginTop: 0 }}>Sessions</h1>
      <p style={{ color: '#64748b' }}>
        Active and historical remote-access sessions.
      </p>
      {error && <div role="alert" style={errorBox}>{error}</div>}
      <div style={tableCard}>
        {sessions.map((session) => (
          <div
            key={session.id}
            data-testid="session-row"
            style={{ padding: 16, borderBottom: '1px solid #e2e8f0' }}
          >
            <strong>{session.device_name || session.device_id}</strong>
            <div>
              {session.user_name || session.user_id} · {session.mode} · {session.state}
            </div>
            {session.state === 'active' && can('session:terminate') && (
              <button
                type="button"
                data-permission="session:terminate"
                data-state="unlocked"
                onClick={() => stopSession(session.id)}
                style={secondaryButton}
              >
                End session
              </button>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}

function AuditView({ orgId }) {
  const [events, setEvents] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    api(`/orgs/${encodeURIComponent(orgId)}/audit?limit=100`)
      .then((result) => setEvents(result.events || []))
      .catch((err) => setError(readableError(err)));
  }, [orgId]);

  return (
    <section>
      <h1 style={{ marginTop: 0 }}>Audit</h1>
      <p style={{ color: '#64748b' }}>Organization security and access events.</p>
      {error && <div role="alert" style={errorBox}>{error}</div>}
      <div style={tableCard}>
        {events.map((event) => (
          <div
            key={event.id}
            data-testid="audit-row"
            style={{ padding: 14, borderBottom: '1px solid #e2e8f0' }}
          >
            <strong>{event.action}</strong>
            <div>
              {event.result} · {event.target_type || '—'} · {event.target_id || '—'}
            </div>
            <small style={{ color: '#64748b' }}>
              {event.at || event.created_at || ''}
            </small>
          </div>
        ))}
      </div>
    </section>
  );
}

function AdminView({ org, can, theme, onUpdated }) {
  const [name, setName] = useState(org.name);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  async function renameOrg() {
    setError('');
    setMessage('');
    try {
      await api(`/orgs/${encodeURIComponent(org.id)}`, {
        method: 'PATCH',
        body: JSON.stringify({ name: name.trim() }),
      });
      setMessage('Organization renamed successfully.');
      await onUpdated();
    } catch (err) {
      setError(readableError(err));
    }
  }

  async function deleteOrg() {
    setError('');
    try {
      await api(`/orgs/${encodeURIComponent(org.id)}`, {
        method: 'DELETE',
      });
      window.location.reload();
    } catch (err) {
      setError(readableError(err));
    }
  }

  return (
    <section>
      <h1 style={{ marginTop: 0 }}>Administration</h1>
      <p style={{ color: '#64748b' }}>Organization configuration and lifecycle controls.</p>

      {message && <div role="status" style={{ ...infoBox, background: theme.soft }}>{message}</div>}
      {error && <div role="alert" style={errorBox}>{error}</div>}

      {can('org:update') && (
        <div style={formCard}>
          <h3 style={{ marginTop: 0 }}>Rename organization</h3>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            style={inputStyle}
          />
          <button
            type="button"
            data-testid="rename-org"
            data-permission="org:update"
            data-state="unlocked"
            onClick={renameOrg}
            style={primaryButton}
          >
            Rename organization
          </button>
        </div>
      )}

      {can('org:delete') && (
        <div style={formCard}>
          <h3 style={{ marginTop: 0 }}>Delete organization</h3>
          <button
            type="button"
            data-testid="delete-org"
            data-permission="org:delete"
            data-state="unlocked"
            onClick={deleteOrg}
            style={{ ...primaryButton, background: '#991b1b' }}
          >
            Delete organization
          </button>
        </div>
      )}
    </section>
  );
}

const loginPage = {
  minHeight: '100vh',
  display: 'grid',
  placeItems: 'center',
  background: 'linear-gradient(135deg, #eef2ff 0%, #f8fafc 50%, #ecfeff 100%)',
  fontFamily: 'Inter, ui-sans-serif, system-ui, sans-serif',
  padding: 24,
};

const centerPage = {
  minHeight: '100vh',
  display: 'grid',
  placeItems: 'center',
  fontFamily: 'Inter, ui-sans-serif, system-ui, sans-serif',
};

const loginCard = {
  width: '100%',
  maxWidth: 460,
  boxSizing: 'border-box',
  background: '#fff',
  padding: 32,
  borderRadius: 18,
  boxShadow: '0 20px 60px rgba(15,23,42,.12)',
};

const eyebrow = {
  display: 'inline-flex',
  padding: '6px 10px',
  borderRadius: 999,
  background: '#eff6ff',
  color: '#1d4ed8',
  fontSize: 12,
  fontWeight: 700,
};

const inputStyle = {
  width: '100%',
  boxSizing: 'border-box',
  padding: 11,
  border: '1px solid #cbd5e1',
  borderRadius: 8,
  margin: '7px 0 16px',
};

const primaryButton = {
  border: 0,
  borderRadius: 8,
  padding: '10px 14px',
  background: '#111827',
  color: '#fff',
  fontWeight: 700,
  cursor: 'pointer',
};

const buttonStyle = {
  border: 0,
  borderRadius: 8,
  padding: '8px 12px',
  cursor: 'pointer',
  background: '#111827',
  color: '#fff',
  fontWeight: 600,
};

const secondaryButton = {
  width: '100%',
  border: '1px solid #e2e8f0',
  background: '#fff',
  borderRadius: 8,
  padding: 9,
  cursor: 'pointer',
};

const errorBox = {
  padding: 12,
  borderRadius: 8,
  background: '#fef2f2',
  border: '1px solid #fecaca',
  color: '#991b1b',
  marginBottom: 18,
};

const emptyBox = {
  padding: 45,
  textAlign: 'center',
  background: '#fff',
  border: '1px solid #e2e8f0',
  borderRadius: 12,
  color: '#64748b',
};

const tableCard = {
  background: '#fff',
  border: '1px solid #e2e8f0',
  borderRadius: 12,
  overflow: 'hidden',
};

const formCard = {
  background: '#fff',
  border: '1px solid #e2e8f0',
  borderRadius: 12,
  padding: 20,
  marginBottom: 18,
};

const pageHeader = {
  display: 'flex',
  alignItems: 'flex-start',
  justifyContent: 'space-between',
  gap: 20,
  marginBottom: 22,
};

const sectionLabel = {
  fontSize: 11,
  color: '#94a3b8',
  fontWeight: 800,
  marginBottom: 8,
};

const infoBox = {
  marginTop: 18,
  padding: 14,
  borderRadius: 10,
  color: '#475569',
  fontSize: 13,
};

const th = {
  textAlign: 'left',
  padding: '12px 16px',
  fontSize: 12,
  color: '#64748b',
  textTransform: 'uppercase',
  letterSpacing: '.04em',
};

const td = {
  padding: '15px 16px',
  verticalAlign: 'middle',
};

createRoot(document.getElementById('root')).render(<App />);

