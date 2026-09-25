import { createHash, createHmac } from 'crypto';
import type {
  AdminUser,
  BackupCodeSet,
  EncryptedTOTPSecret,
} from '../types/auth.js';

export const FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS = 10 * 60 * 1000;
const CLOCK_SKEW_MS = 60 * 1000;
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BCRYPT_HASH_RE =
  /^\$2[aby]\$(?:0[4-9]|[12]\d|3[01])\$[./A-Za-z0-9]{53}$/;
const BACKUP_CODE_HASH_RE = /^[a-f0-9]{64}$/;
const MATERIAL_DIGEST_RE = /^[a-f0-9]{64}$/;
const ACTOR_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const HANDLE_RE = /^[a-zA-Z][a-zA-Z0-9_-]{2,29}$/;
const MATERIAL_DIGEST_DOMAIN = 'tinyland-auth:first-user-bootstrap-material:v1';

const CLAIM_KEYS = ['version', 'tenantId', 'attemptId', 'actor', 'claimedAt'] as const;
const ACTOR_KEYS = [
  'id',
  'handle',
  'isActive',
  'totpEnabled',
  'sessionAuthority',
  'backupCodesGenerated',
] as const;
const FINALIZATION_KEYS = [
  'version',
  'tenantId',
  'attemptId',
  'finalizedAt',
  'user',
  'totpSecret',
  'backupCodes',
] as const;
const USER_REQUIRED_KEYS = [
  'id',
  'handle',
  'passwordHash',
  'totpEnabled',
  'totpSecretId',
  'role',
  'isActive',
  'needsOnboarding',
  'onboardingStep',
  'createdAt',
  'updatedAt',
] as const;
const USER_OPTIONAL_KEYS = [
  'tenantId',
  'email',
  'displayName',
  'permissions',
  'isLocked',
  'lockReason',
  'lockedAt',
  'firstLogin',
  'lastLoginAt',
  'passwordChangedAt',
  'bio',
  'avatarUrl',
  'pronouns',
  'timezone',
  'locale',
  'theme',
  'emailNotifications',
  'loginAttempts',
  'lastFailedLoginAt',
  'ipAddress',
  'userAgent',
  'githubId',
  'githubLogin',
  'githubLinkedAt',
] as const;
const TOTP_REQUIRED_KEYS = [
  'userId',
  'handle',
  'encryptedSecret',
  'iv',
  'authTag',
  'salt',
  'createdAt',
  'backupCodesGenerated',
  'version',
] as const;
const TOTP_OPTIONAL_KEYS = ['lastUsedAt', 'lastUsedTotpStep'] as const;
const BACKUP_CODE_SET_REQUIRED_KEYS = ['userId', 'codes', 'generatedAt'] as const;
const BACKUP_CODE_SET_OPTIONAL_KEYS = ['lastUsedAt'] as const;
const BACKUP_CODE_REQUIRED_KEYS = ['id', 'hash', 'used'] as const;
const BACKUP_CODE_OPTIONAL_KEYS = ['usedAt'] as const;
const RECEIPT_KEYS = [
  'version',
  'tenantId',
  'attemptId',
  'userId',
  'handle',
  'claimedAt',
  'finalizedAt',
  'materialDigest',
] as const;

export interface InertFirstUserActorClaim {
  id: string;
  handle: string;
  isActive: false;
  totpEnabled: false;
  sessionAuthority: false;
  backupCodesGenerated: false;
}

export interface InertFirstUserClaim {
  version: 1;
  tenantId: string;
  attemptId: string;
  actor: InertFirstUserActorClaim;
  claimedAt: string;
}

export interface FirstUserBootstrapFinalization {
  version: 1;
  tenantId: string;
  attemptId: string;
  finalizedAt: string;
  user: AdminUser;
  totpSecret: EncryptedTOTPSecret;
  backupCodes: BackupCodeSet;
}

export interface FirstUserBootstrapReceipt {
  version: 1;
  tenantId: string;
  attemptId: string;
  userId: string;
  handle: string;
  claimedAt: string;
  finalizedAt: string;
  materialDigest: string;
}

export interface FirstUserBootstrapReceiptExpectation {
  claim: InertFirstUserClaim;
  finalization: FirstUserBootstrapFinalization;
}

export class FirstUserBootstrapConflictError extends Error {
  readonly code = 'FIRST_USER_BOOTSTRAP_CONFLICT';

  constructor(message: string) {
    super(message);
    this.name = 'FirstUserBootstrapConflictError';
  }
}

export class FirstUserBootstrapValidationError extends Error {
  readonly code = 'FIRST_USER_BOOTSTRAP_INVALID';

  constructor(message: string) {
    super(message);
    this.name = 'FirstUserBootstrapValidationError';
  }
}

function validationError(message: string): never {
  throw new FirstUserBootstrapValidationError(message);
}

function assertPlainJsonObject(
  value: unknown,
  label: string,
): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    validationError(`${label} must be a JSON object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    validationError(`${label} must be a plain JSON object`);
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') {
      validationError(`${label} cannot contain symbol keys`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
      validationError(`${label}.${key} must be an enumerable JSON value`);
    }
  }
}

function assertExactObjectKeys(
  value: unknown,
  label: string,
  required: readonly string[],
  optional: readonly string[] = [],
): asserts value is Record<string, unknown> {
  assertPlainJsonObject(value, label);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) validationError(`${label}.${key} is not allowed`);
  }
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      validationError(`${label}.${key} is required`);
    }
  }
}

function assertDenseJsonArray(value: unknown, label: string): asserts value is unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    validationError(`${label} must be a JSON array`);
  }
  const allowedKeys = new Set<string>(['length']);
  for (let index = 0; index < value.length; index += 1) {
    const key = String(index);
    allowedKeys.add(key);
    if (!Object.prototype.hasOwnProperty.call(value, index)) {
      validationError(`${label} must not be sparse`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
      validationError(`${label}[${index}] must be an enumerable JSON value`);
    }
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowedKeys.has(key)) {
      validationError(`${label} cannot contain non-index properties`);
    }
  }
}

function canonicalString(
  value: unknown,
  label: string,
  maximumLength: number,
  options: { allowEmpty?: boolean; lowercase?: boolean } = {},
): string {
  if (typeof value !== 'string' || value.includes('\0')) {
    validationError(`${label} must be a string`);
  }
  const trimmed = value.trim();
  const canonical = options.lowercase ? trimmed.toLowerCase() : trimmed;
  if (value !== canonical) {
    validationError(`${label} must already be in canonical form`);
  }
  if ((!options.allowEmpty && canonical.length === 0) || canonical.length > maximumLength) {
    validationError(`${label} has an invalid length`);
  }
  return canonical;
}

function safeIdentity(value: unknown, label: string): string {
  const identity = canonicalString(value, label, 256);
  if (!ACTOR_ID_RE.test(identity)) validationError(`${label} is invalid`);
  return identity;
}

function safeAttemptId(value: unknown, label: string): string {
  const attemptId = canonicalString(value, label, 256);
  if (!/^[A-Za-z0-9._~-]+$/.test(attemptId)) validationError(`${label} is invalid`);
  return attemptId;
}

function canonicalHandle(value: unknown, label: string): string {
  const handle = canonicalString(value, label, 30);
  if (!HANDLE_RE.test(handle)) validationError(`${label} is invalid`);
  return handle;
}

function canonicalBoolean(value: unknown, label: string): boolean {
  if (typeof value !== 'boolean') validationError(`${label} must be a boolean`);
  return value;
}

function canonicalSafeInteger(
  value: unknown,
  label: string,
  minimum: number = 0,
): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < minimum
  ) {
    validationError(`${label} must be a safe integer of at least ${minimum}`);
  }
  return value;
}

function canonicalIso(value: unknown, label: string): string {
  if (typeof value !== 'string') validationError(`${label} must be an ISO timestamp`);
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    validationError(`${label} must be a canonical ISO timestamp`);
  }
  return value;
}

function isoMillis(value: string): number {
  return Date.parse(value);
}

function hasOwn(value: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

export function normalizeFirstUserBootstrapTenantId(value: unknown): string {
  if (typeof value !== 'string' || !UUID_RE.test(value)) {
    validationError('tenantId must be a UUID');
  }
  return value.toLowerCase();
}

function canonicalizeClaim(
  value: unknown,
  nowMs: number | null,
): InertFirstUserClaim {
  assertExactObjectKeys(value, 'claim', CLAIM_KEYS);
  assertExactObjectKeys(value.actor, 'claim.actor', ACTOR_KEYS);
  if (value.version !== 1) validationError('claim.version must be 1');

  const tenantId = normalizeFirstUserBootstrapTenantId(value.tenantId);
  const attemptId = safeAttemptId(value.attemptId, 'claim.attemptId');
  const claimedAt = canonicalIso(value.claimedAt, 'claim.claimedAt');
  const claimedAtMs = isoMillis(claimedAt);
  if (
    nowMs !== null &&
    (claimedAtMs > nowMs + CLOCK_SKEW_MS ||
      claimedAtMs < nowMs - FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS)
  ) {
    validationError('claim.claimedAt is outside the active claim window');
  }

  const actor = value.actor;
  const canonicalActor: InertFirstUserActorClaim = {
    id: safeIdentity(actor.id, 'claim.actor.id'),
    handle: canonicalHandle(actor.handle, 'claim.actor.handle'),
    isActive: false,
    totpEnabled: false,
    sessionAuthority: false,
    backupCodesGenerated: false,
  };
  for (const field of [
    'isActive',
    'totpEnabled',
    'sessionAuthority',
    'backupCodesGenerated',
  ] as const) {
    if (actor[field] !== false) validationError(`claim.actor.${field} must be false`);
  }

  return {
    version: 1,
    tenantId,
    attemptId,
    actor: canonicalActor,
    claimedAt,
  };
}

export function canonicalizeInertFirstUserClaim(
  value: unknown,
  nowMs: number = Date.now(),
): InertFirstUserClaim {
  return canonicalizeClaim(value, nowMs);
}

export function canonicalizeStructuralInertFirstUserClaim(
  value: unknown,
): InertFirstUserClaim {
  return canonicalizeClaim(value, null);
}

export function isValidInertFirstUserClaim(
  value: unknown,
  nowMs: number = Date.now(),
): value is InertFirstUserClaim {
  try {
    canonicalizeInertFirstUserClaim(value, nowMs);
    return true;
  } catch {
    return false;
  }
}

export function isStructurallyValidInertFirstUserClaim(
  value: unknown,
): value is InertFirstUserClaim {
  try {
    canonicalizeStructuralInertFirstUserClaim(value);
    return true;
  } catch {
    return false;
  }
}

export function isExpiredInertFirstUserClaim(
  claim: InertFirstUserClaim,
  nowMs: number = Date.now(),
): boolean {
  let canonical: InertFirstUserClaim;
  try {
    canonical = canonicalizeStructuralInertFirstUserClaim(claim);
  } catch {
    return true;
  }
  return isoMillis(canonical.claimedAt) < nowMs - FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS;
}

function canonicalJson(value: unknown, ancestors: Set<object> = new Set()): string {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      validationError('Bootstrap values cannot contain non-canonical numbers');
    }
    return JSON.stringify(value);
  }
  if (typeof value !== 'object') {
    validationError(`Bootstrap values cannot contain ${typeof value}`);
  }
  if (ancestors.has(value)) validationError('Bootstrap values cannot contain cycles');
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      assertDenseJsonArray(value, 'Bootstrap array');
      return `[${value.map((item) => canonicalJson(item, ancestors)).join(',')}]`;
    }
    assertPlainJsonObject(value, 'Bootstrap object');
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key], ancestors)}`)
      .join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function firstUserBootstrapValueDigest(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

export function firstUserBootstrapValuesEqual(
  left: unknown,
  right: unknown,
): boolean {
  return canonicalJson(left) === canonicalJson(right);
}

export function canonicalizeFirstUserBootstrapClaimResult(
  value: unknown,
  expectedValue: unknown,
): InertFirstUserClaim {
  const expected = canonicalizeStructuralInertFirstUserClaim(expectedValue);
  const returned = canonicalizeStructuralInertFirstUserClaim(value);
  if (
    firstUserBootstrapValueDigest(returned) !==
    firstUserBootstrapValueDigest(expected)
  ) {
    validationError('Storage returned a bootstrap claim that does not match the request');
  }
  return returned;
}

export function firstUserBootstrapMaterialDigest(
  finalization: FirstUserBootstrapFinalization,
): string {
  // This is an equality commitment over already-hashed or encrypted bootstrap
  // material, not a password verifier. Keep it separate from structural digests.
  return scopedMaterialDigest(
    'finalization',
    finalization.tenantId,
    finalization.attemptId,
    finalization,
  );
}

export function firstUserBootstrapPendingAttemptMaterialDigest(
  tenantId: string,
  attemptId: string,
  value: unknown,
): string {
  return scopedMaterialDigest('pending-attempt', tenantId, attemptId, value);
}

function scopedMaterialDigest(
  scope: 'finalization' | 'pending-attempt',
  tenantId: string,
  attemptId: string,
  value: unknown,
): string {
  const key = canonicalJson([MATERIAL_DIGEST_DOMAIN, scope, tenantId, attemptId]);
  return createHmac('sha256', key)
    .update(MATERIAL_DIGEST_DOMAIN)
    .update('\0')
    .update(scope)
    .update('\0')
    .update(canonicalJson(value))
    .digest('hex');
}

function isValidBootstrapEmail(value: string): boolean {
  let atIndex = -1;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character.trim().length === 0) return false;
    if (character === '@') {
      if (atIndex !== -1) return false;
      atIndex = index;
    }
  }
  const finalDotIndex = value.lastIndexOf('.');
  return (
    atIndex > 0 &&
    finalDotIndex > atIndex + 1 &&
    finalDotIndex < value.length - 1
  );
}

function canonicalOptionalString(
  source: Record<string, unknown>,
  target: Record<string, unknown>,
  field: string,
  maximumLength: number,
  options: { lowercase?: boolean } = {},
): void {
  if (hasOwn(source, field)) {
    target[field] = canonicalString(source[field], `finalization.user.${field}`, maximumLength, options);
  }
}

function canonicalizeUser(value: unknown): AdminUser & { tenantId?: string } {
  assertExactObjectKeys(value, 'finalization.user', USER_REQUIRED_KEYS, USER_OPTIONAL_KEYS);
  const user: Record<string, unknown> = {
    id: safeIdentity(value.id, 'finalization.user.id'),
    handle: canonicalHandle(value.handle, 'finalization.user.handle'),
    passwordHash: canonicalString(value.passwordHash, 'finalization.user.passwordHash', 256),
    totpEnabled: canonicalBoolean(value.totpEnabled, 'finalization.user.totpEnabled'),
    totpSecretId: canonicalHandle(value.totpSecretId, 'finalization.user.totpSecretId'),
    role: value.role,
    isActive: canonicalBoolean(value.isActive, 'finalization.user.isActive'),
    needsOnboarding: canonicalBoolean(
      value.needsOnboarding,
      'finalization.user.needsOnboarding',
    ),
    onboardingStep: canonicalSafeInteger(
      value.onboardingStep,
      'finalization.user.onboardingStep',
    ),
    createdAt: canonicalIso(value.createdAt, 'finalization.user.createdAt'),
    updatedAt: canonicalIso(value.updatedAt, 'finalization.user.updatedAt'),
  };

  if (!BCRYPT_HASH_RE.test(user.passwordHash as string)) {
    validationError('finalization.user.passwordHash must be a structurally valid bcrypt hash');
  }
  if (user.role !== 'super_admin' || user.isActive !== true || user.totpEnabled !== true) {
    validationError('Finalized first user must be an active super_admin with TOTP enabled');
  }
  if (user.totpSecretId !== user.handle) {
    validationError('finalization.user.totpSecretId must match the user handle');
  }

  if (hasOwn(value, 'tenantId')) {
    user.tenantId = normalizeFirstUserBootstrapTenantId(value.tenantId);
  }
  if (hasOwn(value, 'email')) {
    const email = canonicalString(value.email, 'finalization.user.email', 320, { lowercase: true });
    if (!isValidBootstrapEmail(email)) {
      validationError('finalization.user.email is invalid');
    }
    user.email = email;
  }
  canonicalOptionalString(value, user, 'displayName', 256);
  canonicalOptionalString(value, user, 'bio', 4096);
  canonicalOptionalString(value, user, 'avatarUrl', 2048);
  canonicalOptionalString(value, user, 'pronouns', 128);
  canonicalOptionalString(value, user, 'timezone', 128);
  canonicalOptionalString(value, user, 'locale', 64);
  canonicalOptionalString(value, user, 'ipAddress', 256);
  canonicalOptionalString(value, user, 'userAgent', 2048);

  if (hasOwn(value, 'permissions')) {
    assertDenseJsonArray(value.permissions, 'finalization.user.permissions');
    const permissions = value.permissions.map((permission, index) =>
      canonicalString(permission, `finalization.user.permissions[${index}]`, 128),
    );
    if (new Set(permissions).size !== permissions.length) {
      validationError('finalization.user.permissions must be unique');
    }
    const sortedPermissions = [...permissions].sort();
    if (permissions.some((permission, index) => permission !== sortedPermissions[index])) {
      validationError('finalization.user.permissions must be sorted canonically');
    }
    user.permissions = permissions;
  }
  if (hasOwn(value, 'isLocked')) {
    const isLocked = canonicalBoolean(value.isLocked, 'finalization.user.isLocked');
    if (isLocked) validationError('Finalized first user must not be locked');
    user.isLocked = false;
  }
  if (hasOwn(value, 'lockReason') || hasOwn(value, 'lockedAt')) {
    validationError('Finalized first user cannot contain prior lock state');
  }
  if (hasOwn(value, 'firstLogin')) {
    user.firstLogin = canonicalBoolean(value.firstLogin, 'finalization.user.firstLogin');
  }
  if (hasOwn(value, 'lastLoginAt') || hasOwn(value, 'lastFailedLoginAt')) {
    validationError('Finalized first user cannot contain prior login state');
  }
  if (hasOwn(value, 'passwordChangedAt')) {
    user.passwordChangedAt = canonicalIso(
      value.passwordChangedAt,
      'finalization.user.passwordChangedAt',
    );
  }
  if (hasOwn(value, 'theme')) {
    if (value.theme !== 'light' && value.theme !== 'dark' && value.theme !== 'auto') {
      validationError('finalization.user.theme is invalid');
    }
    user.theme = value.theme;
  }
  if (hasOwn(value, 'emailNotifications')) {
    user.emailNotifications = canonicalBoolean(
      value.emailNotifications,
      'finalization.user.emailNotifications',
    );
  }
  if (hasOwn(value, 'loginAttempts')) {
    const loginAttempts = canonicalSafeInteger(
      value.loginAttempts,
      'finalization.user.loginAttempts',
    );
    if (loginAttempts !== 0) validationError('Finalized first user cannot have failed login attempts');
    user.loginAttempts = 0;
  }

  const githubFields = ['githubId', 'githubLogin', 'githubLinkedAt'] as const;
  const presentGithubFields = githubFields.filter((field) => hasOwn(value, field));
  if (presentGithubFields.length > 0 && presentGithubFields.length !== githubFields.length) {
    validationError('Finalized GitHub identity must be complete or absent');
  }
  if (presentGithubFields.length === githubFields.length) {
    if (value.githubId === null && value.githubLogin === null && value.githubLinkedAt === null) {
      user.githubId = null;
      user.githubLogin = null;
      user.githubLinkedAt = null;
    } else {
      user.githubId = canonicalSafeInteger(value.githubId, 'finalization.user.githubId', 1);
      user.githubLogin = canonicalString(value.githubLogin, 'finalization.user.githubLogin', 256);
      user.githubLinkedAt = canonicalIso(
        value.githubLinkedAt,
        'finalization.user.githubLinkedAt',
      );
    }
  }

  return user as unknown as AdminUser & { tenantId?: string };
}

function canonicalizeTotpSecret(value: unknown): EncryptedTOTPSecret {
  assertExactObjectKeys(value, 'finalization.totpSecret', TOTP_REQUIRED_KEYS, TOTP_OPTIONAL_KEYS);
  if (hasOwn(value, 'lastUsedAt') || hasOwn(value, 'lastUsedTotpStep')) {
    validationError('Finalized TOTP factor must be fresh and unused');
  }
  const version = canonicalSafeInteger(value.version, 'finalization.totpSecret.version', 1);
  if (value.backupCodesGenerated !== true) {
    validationError('finalization.totpSecret.backupCodesGenerated must be true');
  }
  return {
    userId: safeIdentity(value.userId, 'finalization.totpSecret.userId'),
    handle: canonicalHandle(value.handle, 'finalization.totpSecret.handle'),
    encryptedSecret: canonicalString(
      value.encryptedSecret,
      'finalization.totpSecret.encryptedSecret',
      16_384,
    ),
    iv: canonicalString(value.iv, 'finalization.totpSecret.iv', 4096),
    authTag: canonicalString(value.authTag, 'finalization.totpSecret.authTag', 4096),
    salt: canonicalString(value.salt, 'finalization.totpSecret.salt', 4096),
    createdAt: canonicalIso(value.createdAt, 'finalization.totpSecret.createdAt'),
    backupCodesGenerated: true,
    version,
  };
}

function canonicalizeBackupCodes(value: unknown): BackupCodeSet {
  assertExactObjectKeys(
    value,
    'finalization.backupCodes',
    BACKUP_CODE_SET_REQUIRED_KEYS,
    BACKUP_CODE_SET_OPTIONAL_KEYS,
  );
  if (hasOwn(value, 'lastUsedAt')) {
    validationError('Finalized backup-code set must be fresh and unused');
  }
  assertDenseJsonArray(value.codes, 'finalization.backupCodes.codes');
  if (value.codes.length === 0) {
    validationError('At least one fresh backup-code record is required');
  }
  const ids = new Set<string>();
  const hashes = new Set<string>();
  const codes = value.codes.map((code, index) => {
    const label = `finalization.backupCodes.codes[${index}]`;
    assertExactObjectKeys(code, label, BACKUP_CODE_REQUIRED_KEYS, BACKUP_CODE_OPTIONAL_KEYS);
    if (hasOwn(code, 'usedAt') || code.used !== false) {
      validationError(`${label} must be fresh and unused`);
    }
    const id = safeIdentity(code.id, `${label}.id`);
    const hash = canonicalString(code.hash, `${label}.hash`, 64, { lowercase: true });
    if (!BACKUP_CODE_HASH_RE.test(hash) || ids.has(id) || hashes.has(hash)) {
      validationError('Backup-code records must have unique ids and SHA-256 hashes');
    }
    ids.add(id);
    hashes.add(hash);
    return { id, hash, used: false };
  });
  return {
    userId: safeIdentity(value.userId, 'finalization.backupCodes.userId'),
    codes,
    generatedAt: canonicalIso(
      value.generatedAt,
      'finalization.backupCodes.generatedAt',
    ),
  };
}

export function canonicalizeFirstUserBootstrapFinalizationPayload(
  value: unknown,
): FirstUserBootstrapFinalization {
  assertExactObjectKeys(value, 'finalization', FINALIZATION_KEYS);
  if (value.version !== 1) validationError('finalization.version must be 1');
  const finalization: FirstUserBootstrapFinalization = {
    version: 1,
    tenantId: normalizeFirstUserBootstrapTenantId(value.tenantId),
    attemptId: safeAttemptId(value.attemptId, 'finalization.attemptId'),
    finalizedAt: canonicalIso(value.finalizedAt, 'finalization.finalizedAt'),
    user: canonicalizeUser(value.user),
    totpSecret: canonicalizeTotpSecret(value.totpSecret),
    backupCodes: canonicalizeBackupCodes(value.backupCodes),
  };
  const claimedAt = isoMillis(finalization.user.createdAt);
  const finalizedAt = isoMillis(finalization.finalizedAt);
  if (
    finalizedAt < claimedAt ||
    finalizedAt > claimedAt + FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS
  ) {
    validationError('Finalization is outside the first-user claim lifetime');
  }
  return finalization;
}

function assertTimestampInFinalizationWindow(
  label: string,
  value: string,
  claimedAt: number,
  finalizedAt: number,
): void {
  const timestamp = isoMillis(value);
  if (timestamp < claimedAt || timestamp > finalizedAt) {
    validationError(`${label} must be between claim and finalization`);
  }
}

export function canonicalizeFirstUserBootstrapFinalization(
  claimValue: unknown,
  finalizationValue: unknown,
  nowMs: number = Date.now(),
): FirstUserBootstrapFinalization {
  const claim = canonicalizeStructuralInertFirstUserClaim(claimValue);
  const finalization = canonicalizeFirstUserBootstrapFinalizationPayload(finalizationValue);
  if (
    finalization.tenantId !== claim.tenantId ||
    finalization.attemptId !== claim.attemptId
  ) {
    throw new FirstUserBootstrapConflictError(
      'Bootstrap tenant or attempt does not match the active claim',
    );
  }
  if (finalization.user.id !== claim.actor.id || finalization.user.handle !== claim.actor.handle) {
    throw new FirstUserBootstrapConflictError(
      'Finalization user does not match the claimed actor',
    );
  }
  if (finalization.user.createdAt !== claim.claimedAt) {
    throw new FirstUserBootstrapConflictError(
      'Finalization claim timestamp does not match the active claim',
    );
  }
  const materialTenantId = (finalization.user as AdminUser & { tenantId?: string }).tenantId;
  if (materialTenantId !== undefined && materialTenantId !== claim.tenantId) {
    throw new FirstUserBootstrapConflictError(
      'Finalization user tenant does not match the claim',
    );
  }
  if (
    finalization.totpSecret.userId !== finalization.user.id ||
    finalization.totpSecret.handle !== finalization.user.handle ||
    finalization.backupCodes.userId !== finalization.user.id
  ) {
    throw new FirstUserBootstrapConflictError(
      'Finalized factor identity does not match the claimed actor',
    );
  }

  const claimedAt = isoMillis(claim.claimedAt);
  const finalizedAt = isoMillis(finalization.finalizedAt);
  if (
    finalizedAt < claimedAt ||
    finalizedAt > claimedAt + FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS ||
    finalizedAt > nowMs + CLOCK_SKEW_MS ||
    nowMs > claimedAt + FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS
  ) {
    validationError('Finalization timestamp is outside the active claim window');
  }
  assertTimestampInFinalizationWindow(
    'finalization.user.createdAt',
    finalization.user.createdAt,
    claimedAt,
    finalizedAt,
  );
  assertTimestampInFinalizationWindow(
    'finalization.user.updatedAt',
    finalization.user.updatedAt,
    claimedAt,
    finalizedAt,
  );
  assertTimestampInFinalizationWindow(
    'finalization.totpSecret.createdAt',
    finalization.totpSecret.createdAt,
    claimedAt,
    finalizedAt,
  );
  assertTimestampInFinalizationWindow(
    'finalization.backupCodes.generatedAt',
    finalization.backupCodes.generatedAt,
    claimedAt,
    finalizedAt,
  );
  const optionalTimestamps = [
    ['finalization.user.passwordChangedAt', finalization.user.passwordChangedAt],
    [
      'finalization.user.githubLinkedAt',
      finalization.user.githubLinkedAt === null
        ? undefined
        : finalization.user.githubLinkedAt,
    ],
  ] as const;
  for (const [label, timestamp] of optionalTimestamps) {
    if (timestamp !== undefined) {
      assertTimestampInFinalizationWindow(label, timestamp, claimedAt, finalizedAt);
    }
  }
  return finalization;
}

export function assertValidFirstUserBootstrapFinalization(
  claim: InertFirstUserClaim,
  finalization: unknown,
  nowMs: number = Date.now(),
): asserts finalization is FirstUserBootstrapFinalization {
  canonicalizeFirstUserBootstrapFinalization(claim, finalization, nowMs);
}

export function createFirstUserBootstrapReceipt(
  claimValue: InertFirstUserClaim,
  finalizationValue: FirstUserBootstrapFinalization,
): FirstUserBootstrapReceipt {
  const finalizedAtMs = isoMillis(canonicalIso(finalizationValue.finalizedAt, 'finalization.finalizedAt'));
  const claim = canonicalizeStructuralInertFirstUserClaim(claimValue);
  const finalization = canonicalizeFirstUserBootstrapFinalization(
    claim,
    finalizationValue,
    finalizedAtMs,
  );
  return {
    version: 1,
    tenantId: claim.tenantId,
    attemptId: claim.attemptId,
    userId: claim.actor.id,
    handle: claim.actor.handle,
    claimedAt: claim.claimedAt,
    finalizedAt: finalization.finalizedAt,
    materialDigest: firstUserBootstrapMaterialDigest(finalization),
  };
}

export function parseFirstUserBootstrapReceipt(
  value: unknown,
  expected?: FirstUserBootstrapReceiptExpectation,
): FirstUserBootstrapReceipt {
  assertExactObjectKeys(value, 'receipt', RECEIPT_KEYS);
  if (value.version !== 1) validationError('receipt.version must be 1');
  const receipt: FirstUserBootstrapReceipt = {
    version: 1,
    tenantId: normalizeFirstUserBootstrapTenantId(value.tenantId),
    attemptId: safeAttemptId(value.attemptId, 'receipt.attemptId'),
    userId: safeIdentity(value.userId, 'receipt.userId'),
    handle: canonicalHandle(value.handle, 'receipt.handle'),
    claimedAt: canonicalIso(value.claimedAt, 'receipt.claimedAt'),
    finalizedAt: canonicalIso(value.finalizedAt, 'receipt.finalizedAt'),
    materialDigest: canonicalString(value.materialDigest, 'receipt.materialDigest', 64, {
      lowercase: true,
    }),
  };
  const claimedAt = isoMillis(receipt.claimedAt);
  const finalizedAt = isoMillis(receipt.finalizedAt);
  if (
    !MATERIAL_DIGEST_RE.test(receipt.materialDigest) ||
    finalizedAt < claimedAt ||
    finalizedAt > claimedAt + FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS
  ) {
    validationError('Bootstrap receipt digest or timestamps are invalid');
  }
  if (expected) {
    const canonical = createFirstUserBootstrapReceipt(
      expected.claim,
      expected.finalization,
    );
    if (firstUserBootstrapValueDigest(receipt) !== firstUserBootstrapValueDigest(canonical)) {
      validationError('Bootstrap receipt does not match its claim and finalized material');
    }
  }
  return receipt;
}

export function parseFirstUserBootstrapReceiptForFinalization(
  value: unknown,
  finalizationValue: unknown,
): FirstUserBootstrapReceipt {
  const finalization = canonicalizeFirstUserBootstrapFinalizationPayload(finalizationValue);
  const receipt = parseFirstUserBootstrapReceipt(value);
  if (
    receipt.tenantId !== finalization.tenantId ||
    receipt.attemptId !== finalization.attemptId ||
    receipt.userId !== finalization.user.id ||
    receipt.handle !== finalization.user.handle ||
    receipt.claimedAt !== finalization.user.createdAt ||
    receipt.finalizedAt !== finalization.finalizedAt ||
    receipt.materialDigest !== firstUserBootstrapMaterialDigest(finalization)
  ) {
    validationError('Storage returned a bootstrap receipt that does not match finalization');
  }
  return receipt;
}

export function parseFirstUserBootstrapReceiptForTenant(
  value: unknown,
  tenantIdValue: unknown,
): FirstUserBootstrapReceipt {
  const tenantId = normalizeFirstUserBootstrapTenantId(tenantIdValue);
  const receipt = parseFirstUserBootstrapReceipt(value);
  if (receipt.tenantId !== tenantId) {
    validationError('Storage returned a bootstrap receipt for a different tenant');
  }
  return receipt;
}

export function cloneBootstrapValue<T>(value: T): T {
  return structuredClone(value);
}
