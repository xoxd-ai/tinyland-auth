/**
 * Server-only SvelteKit adapter entry. Keep client rune stores out of this
 * graph so plain Node server consumers can import these helpers directly.
 */

export {
  setSessionCookie,
  setAuthDataCookie,
  clearSessionCookies,
  getSessionIdFromCookies,
  sessionConfigToCookieConfig,
  type CookieConfig,
  DEFAULT_COOKIE_CONFIG,
} from './session-cookies.js';

export {
  requireAuth,
  requireRole,
  requirePermission,
  adminGuard,
  canManageTargetRole,
  checkAuth,
  protectEndpoint,
  getSessionFromLocals,
  getUserFromLocals,
  type GuardOptions,
  type GuardResult,
} from './guards.js';

export {
  createAuthHandle,
  createCSRFHandle,
  sequence,
  getClientIp,
  type AuthHandleConfig,
} from './hook.js';

export {
  requireContentEditPermission,
  requireContentDeletePermission,
  isContentOwner,
  canEditOwnedContent,
  canDeleteOwnedContent,
  isSoleOwner,
  type OwnershipUser,
  type OwnedContent,
} from './ownership.js';

export {
  extractCertificateFromEvent,
  requireMTLS,
  getCertificateFingerprintFromEvent,
  type CertificateHeaders,
  type CertificateInfo,
  type MTLSOptions,
} from './mtls.js';
