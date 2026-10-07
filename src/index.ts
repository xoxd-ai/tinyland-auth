
































export {
  ADMIN_ROLES,
  AdminRole,
  ROLE_HIERARCHY,
  ROLE_MANAGEMENT_ORDER,
  AuditEventType,
  AuthErrorCode,
  isAdminUser,
  isValidAdminRole,
  hasHigherRole,
  hasEqualOrHigherRole,
  DEFAULT_AUTH_CONFIG,
  createAuthConfig,
  PERMISSIONS,
  ROLE_PERMISSIONS,
  MEMBER_SELF_SERVICE_CORE,
  FEATURE_DOMAINS,
  PERMISSION_FEATURE_DOMAIN,
  ROLE_CHARTER,
  VALIDATION_RULES,
} from './types/index.js';


export type {
  AdminUser,
  DeviceType,
  Session,
  SessionUser,
  SessionMetadata,
  TOTPSecret,
  EncryptedTOTPSecret,
  EncryptedData,
  BackupCode,
  BackupCodeSet,
  EncryptedBackupCode,
  AdminInvitation,
  AuditSeverity,
  AuditEvent,
  AuthError,
  AuthConfig,
  TOTPConfig,
  SessionConfig,
  PasswordConfig,
  RateLimitConfig,
  InvitationConfig,
  BackupCodesConfig,
  SecurityConfig,
  AdminPermission,
  ContentVisibility,
  FeatureDomain,
  RoleAxis,
  RoleCharterEntry,
  
  BootstrapRequest,
  BootstrapResponse,
  BootstrapVerificationRequest,
  BootstrapStatus,
  LoginRequest,
  LoginResponse,
  LogoutRequest,
  LogoutResponse,
  SessionInfo,
  SessionRefreshRequest,
  SessionRefreshResponse,
  SessionListResponse,
  SessionTerminateRequest,
  SessionTerminateResponse,
  InvitationCreateRequest,
  InvitationCreateResponse,
  InvitationAcceptRequest,
  InvitationAcceptResponse,
  InvitationListResponse,
  InvitationRevokeRequest,
  InvitationRevokeResponse,
  OnboardingStatus,
  ProfileSetupRequest,
  SecurityReviewRequest,
  PreferencesSetupRequest,
  OnboardingStepResponse,
  OnboardingSkipRequest,
  TOTPSetupRequest,
  TOTPSetupResponse,
  TOTPDisableRequest,
  TOTPDisableResponse,
  BackupCodeUsageRequest,
  BackupCodeUsageResponse,
  BackupCodesRegenerateRequest,
  BackupCodesRegenerateResponse,
  PasswordChangeRequest,
  PasswordChangeResponse,
  UserListRequest,
  UserListResponse,
  UserUpdateRequest,
  UserUpdateResponse,
  UserDeleteRequest,
  UserDeleteResponse,
} from './types/index.js';





export {
  
  getRolePermissions,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  requirePermission,
  requireAnyPermission,
  requireAllPermissions,
  getUserPermissions,
  canManageRole,
  isValidPermission,
  getPermissionDisplayName,

  
  canViewPosts,
  canCreatePosts,
  canEditPosts,
  canDeletePosts,
  canViewEvents,
  canCreateEvents,
  canEditEvents,
  canDeleteEvents,
  canViewProfiles,
  canCreateProfiles,
  canEditOwnProfile,
  canEditAnyProfile,
  canDeleteProfiles,
  canViewUsers,
  canManageUsers,
  canViewVideos,
  canCreateVideos,
  canEditVideos,
  canDeleteVideos,

  
  canCreatePublicContent,
  canCreateMemberOnlyContent,
  canFeatureProfile,
  canEditOwnContent,
  canDeleteOwnContent,
  canEditContent,
  canDeleteContent,
  isMemberRole,
  canViewMemberOnlyContent,
  canDeliverFederation,
  getAllowedVisibilityOptions,

  
  canViewContent,
  filterContentByVisibility,

  
  isContentOwner,
  canEditOwnedContent,
  canDeleteOwnedContent,
  requireContentEditPermission,
  requireContentDeletePermission,
  isSoleOwner,
  type OwnershipUser,
  type OwnedContent,
  type OwnershipError,
} from './core/permissions/index.js';





export {
  constantTimeCompare,
  timingSafeVerify,
  timingSafeQuery,
  timingSafeError,
  hashIp,
  maskIp,
  validatePassword,
  type PasswordValidationResult,
  type PasswordPolicy,
  TimingMetrics,
  timingMetrics,
  
  hashPassword,
  verifyPassword,
  needsRehash,
  getHashRounds,
  generateSecurePassword,
  type PasswordHashConfig,
  
  extractCertificate,
  getCertificateFingerprint,
  type CertificateHeaders,
  type CertificateInfo,
  type MTLSOptions,
} from './core/security/index.js';





export {
  TOTPService,
  createTOTPService,
  type TOTPServiceConfig,
} from './core/totp/index.js';





export {
  generateBackupCodes,
  hashBackupCode,
  createBackupCodeSet,
  verifyBackupCode,
  getRemainingCodesCount,
  hasUnusedCodes,
  isValidCodeFormat,
  formatCodesForDisplay,
  shouldRegenerateCodes,
  DEFAULT_BACKUP_CODES_CONFIG,
} from './core/backup-codes/index.js';





export {
  SessionManager,
  createSessionManager,
  classifyDevice,
  extractBrowserInfo,
  type SessionManagerConfig,
  
  createActivityTracker,
  type ActivityTrackingConfig,
  type ActivityType,
  type ActivityEvent,
} from './core/session/index.js';





export {
  type IStorageAdapter,
  type AdminIdentityStorage,
  type BootstrapStorage,
  type HandleValidationStorage,
  type SessionStorage,
  type ActivityTrackingStorage,
  type InvitationStorage,
  type AuditStorage,
  type AuditEventFilters,
  type StorageAdapterConfig,
  MemoryStorageAdapter,
  FileStorageAdapter,
  createFileStorageAdapter,
  type FileStorageConfig,
} from './storage/index.js';





export {
  AuditLogger,
  createAuditLogger,
  getSeverityForEventType,
  type AuditLoggerConfig,
} from './modules/audit/index.js';

// NOTE: InvitationService (src/modules/invitation) is intentionally NOT exported.
// The authoritative, fail-closed invite flow is the standalone
// @tummycrypt/tinyland-invitation package (TIN-1607 consolidation, tinyland.dev
// PR #649). tinyland-auth's local InvitationService.createInvitation performs no
// role authorization, so exporting it was a shelf-grab trap (TIN-2780). It is now
// internal-only and unreachable via the package "exports" map.




export {
  BootstrapService,
  createBootstrapService,
  type BootstrapServiceConfig,
  type BootstrapState,
} from './modules/bootstrap/index.js';





export {
  generateTOTPSecret,
  generateTOTPUri,
  generateTempPassword,
  generateTOTPQRCode,
  generateTOTPToken,
  getTOTPTimeRemaining,
} from './totp/compat.js';





export {
  generateTextCredentialsCard,
  maskPassword,
  escapeXml,
  type CredentialsCardData,
  type CardDesignOptions,
} from './cred-gen/generator.js';

export {
  generateUserCredentials,
  generateCredentialsEmailHtml,
  generateSecureCredentialsLink,
  createCredentialsDownloadResponse,
  type UserCredentials,
} from './cred-gen/helpers.js';





export {
  validateHandle,
  addHandle,
  removeHandle,
  listHandles,
  type HandleValidatorConfig,
  type HandleValidationResult,
} from './validation/handle-validator.js';
