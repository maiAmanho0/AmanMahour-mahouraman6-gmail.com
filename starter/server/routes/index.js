import { registerAuthRoutes } from './auth.js';
import { registerOrgRoutes } from './orgs.js';
import { registerDeviceRoutes } from './devices.js';
import { registerSessionRoutes } from './sessions.js';
import { registerAuditRoutes } from './audit.js';

export function registerRoutes(router, deps) {
  const { db, secret } = deps;
  registerAuthRoutes(router, { db, secret });
  // Org routes must come before devices/sessions: /members/me must be registered
  // before /members/:userId (first match wins in the router).
  registerOrgRoutes(router, { db });
  registerDeviceRoutes(router, { db });
  registerSessionRoutes(router, { db });
  registerAuditRoutes(router, { db });
}


