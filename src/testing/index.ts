/**
 * Test-only harness seams for `@tummycrypt/tinyland-auth`.
 *
 * Reachable ONLY through the explicit `@tummycrypt/tinyland-auth/testing`
 * subpath. Nothing here is re-exported from the package index or from any
 * other subpath (`tests/testing-isolation.test.ts` walks the import graph to
 * prove it), so an application bundle contains this module only if the
 * application imports it by name.
 *
 * Everything that can admit an identity is additionally gated at runtime and
 * fails closed: `NODE_ENV=production` always refuses, and any other
 * environment must opt in with `TINYLAND_AUTH_TEST_ADMISSION=enabled`.
 * Production first-admin bootstrap stays the attended `BootstrapService` flow.
 *
 * Consumers must still keep the import out of production builds (a build-time
 * flag around a dynamic import, plus a bundle assertion); this gate is the
 * second line, not the first.
 */
import { createHash, randomBytes } from 'crypto';
import type { Clock } from '../core/clock/index.js';
import type { BackupCodeGenerator } from '../core/backup-codes/index.js';
import { createBackupCodeSet, generateBackupCodes } from '../core/backup-codes/index.js';
import { generateSecurePassword, hashPassword } from '../core/security/password.js';
import { generateAuthenticatorSecret } from '../totp/otplib-compat.js';
import type { IStorageAdapter } from '../storage/interface.js';
import type {
  AdminUser,
  EncryptedTOTPSecret,
  Session,
  SessionMetadata,
} from '../types/auth.js';
import { ADMIN_ROLES } from '../types/auth.js';

type AdminRole = AdminUser['role'];

/** Environment variable a non-production environment must set to opt in. */
export const TEST_ADMISSION_ENV = 'TINYLAND_AUTH_TEST_ADMISSION';

/** The only value of {@link TEST_ADMISSION_ENV} that opts in. */
export const TEST_ADMISSION_ENV_ENABLED = 'enabled';

export type TestAdmissionEnv = Record<string, string | undefined>;

export class TestAdmissionDisabledError extends Error {
  constructor(reason: string) {
    super(`tinyland-auth test admission is disabled: ${reason}`);
    this.name = 'TestAdmissionDisabledError';
  }
}

export function isTestAdmissionAllowed(env: TestAdmissionEnv = process.env): boolean {
  return (
    env.NODE_ENV !== 'production' &&
    env[TEST_ADMISSION_ENV] === TEST_ADMISSION_ENV_ENABLED
  );
}

/**
 * Throws unless test admission is explicitly enabled in a non-production
 * environment. Production wins over the opt-in flag.
 */
export function assertTestAdmissionAllowed(env: TestAdmissionEnv = process.env): void {
  if (env.NODE_ENV === 'production') {
    throw new TestAdmissionDisabledError('NODE_ENV is production');
  }
  if (env[TEST_ADMISSION_ENV] !== TEST_ADMISSION_ENV_ENABLED) {
    throw new TestAdmissionDisabledError(
      `${TEST_ADMISSION_ENV} is not "${TEST_ADMISSION_ENV_ENABLED}"`,
    );
  }
}

/** A clock a harness can move by hand. */
export interface ManualClock extends Clock {
  set(epochMs: number): void;
  advance(deltaMs: number): void;
}

export function createManualClock(startMs: number): ManualClock {
  let current = startMs;
  return {
    now: () => current,
    set: (epochMs) => {
      current = epochMs;
    },
    advance: (deltaMs) => {
      current += deltaMs;
    },
  };
}

/**
 * Recovery-code generator whose output is a pure function of `seed`. Pass a
 * per-run seed; the codes match the production `XXXX-XXXX` format. Never use
 * outside tests: the codes are predictable by construction.
 */
export function createDeterministicBackupCodeGenerator(seed: string): BackupCodeGenerator {
  if (!seed) {
    throw new Error('A non-empty seed is required');
  }
  let batch = 0;
  return (count: number) => {
    const current = batch++;
    return Array.from({ length: count }, (_, index) => {
      const hex = createHash('sha256')
        .update(`${seed}:${current}:${index}`)
        .digest('hex')
        .toUpperCase();
      return `${hex.slice(0, 4)}-${hex.slice(4, 8)}`;
    });
  };
}

/** Generated, per-run credentials for one test identity. */
export interface TestIdentity {
  role: AdminRole;
  handle: string;
  email: string;
  displayName: string;
  password: string;
  totpSecret: string;
}

/**
 * Generate a fresh identity for one run. Handle, password and TOTP seed all
 * come from the CSPRNG; nothing is fixed, so a leaked fixture is worthless.
 * The email uses the reserved `.test` TLD (RFC 6761) for mail-capture sinks.
 */
export function generateTestIdentity(
  role: AdminRole,
  options: { runId?: string; emailDomain?: string } = {},
): TestIdentity {
  if (!ADMIN_ROLES.includes(role)) {
    throw new Error(`Unknown role: ${String(role)}`);
  }
  const runId = options.runId ?? randomBytes(4).toString('hex');
  const suffix = randomBytes(3).toString('hex');
  const handle = `ax-${role.replace(/_/g, '-')}-${runId}-${suffix}`.slice(0, 30);
  return {
    role,
    handle,
    email: `${handle}@${options.emailDomain ?? 'ax-harness.test'}`,
    displayName: `AX ${role} ${runId}`,
    password: generateSecurePassword(24),
    totpSecret: generateAuthenticatorSecret(),
  };
}

export interface TestAdmissionRequest {
  role: AdminRole;
  /** Supply to reuse an identity; otherwise one is generated. */
  identity?: TestIdentity;
  /** Also mint a session for the admitted user. Defaults to true. */
  createSession?: boolean;
  sessionMetadata?: SessionMetadata;
}

export interface TestAdmission {
  user: Omit<AdminUser, 'passwordHash'>;
  identity: TestIdentity;
  backupCodes: string[];
  session?: Session;
}

/**
 * Admits a generated identity at a requested role without the browser flow.
 * The interface is deliberately small so Keycloak- and tsidp-backed harnesses
 * can implement the same contract against their own identity source.
 */
export interface TestAdmissionIssuer {
  admit(request: TestAdmissionRequest): Promise<TestAdmission>;
}

export type TestAdmissionStorage = Pick<
  IStorageAdapter,
  | 'getUserByHandle'
  | 'createUser'
  | 'saveTOTPSecret'
  | 'saveBackupCodes'
  | 'createSession'
  | 'logAuditEvent'
>;

export interface TestAdmissionIssuerConfig {
  storage: TestAdmissionStorage;
  /** Same contract as `BootstrapServiceConfig.encryptTOTPSecret`. */
  encryptTOTPSecret: (handle: string, secret: string) => Promise<EncryptedTOTPSecret>;
  bcryptRounds?: number;
  backupCodesCount?: number;
  generateBackupCodes?: BackupCodeGenerator;
  clock?: Clock;
  /** Environment to gate on. Defaults to `process.env`, read on every call. */
  env?: TestAdmissionEnv;
}

export function createTestAdmissionIssuer(config: TestAdmissionIssuerConfig): TestAdmissionIssuer {
  const readEnv = () => config.env ?? process.env;
  assertTestAdmissionAllowed(readEnv());

  const nowIso = () => new Date(config.clock ? config.clock.now() : Date.now()).toISOString();

  return {
    async admit(request) {
      assertTestAdmissionAllowed(readEnv());

      const identity = request.identity ?? generateTestIdentity(request.role);
      if (identity.role !== request.role) {
        throw new Error('Identity role does not match the requested role');
      }
      if (await config.storage.getUserByHandle(identity.handle)) {
        throw new Error(`Handle already exists: ${identity.handle}`);
      }

      const passwordHash = await hashPassword(identity.password, {
        rounds: config.bcryptRounds ?? 4,
      });
      const encrypted = await config.encryptTOTPSecret(identity.handle, identity.totpSecret);
      await config.storage.saveTOTPSecret(identity.handle, encrypted);

      const timestamp = nowIso();
      const user = await config.storage.createUser({
        handle: identity.handle,
        email: identity.email,
        displayName: identity.displayName,
        passwordHash,
        role: identity.role,
        isActive: true,
        totpEnabled: true,
        totpSecretId: identity.handle,
        needsOnboarding: false,
        onboardingStep: 0,
        createdAt: timestamp,
        updatedAt: timestamp,
      });

      const backupCodes = (config.generateBackupCodes ?? generateBackupCodes)(
        config.backupCodesCount ?? 10,
      );
      await config.storage.saveBackupCodes(user.id, createBackupCodeSet(user.id, backupCodes));

      const session =
        request.createSession === false
          ? undefined
          : await config.storage.createSession(user.id, user, request.sessionMetadata);

      await config.storage.logAuditEvent({
        timestamp,
        type: 'TEST_ADMISSION' as never,
        userId: user.id,
        handle: user.handle,
        details: { role: user.role, testAdmission: true, sessionIssued: Boolean(session) },
        severity: 'warning',
        source: 'system',
      });

      const { passwordHash: _omitted, ...safeUser } = user;
      return { user: safeUser, identity, backupCodes, session };
    },
  };
}
