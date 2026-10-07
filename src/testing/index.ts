/**
 * Test-only harness for `@tummycrypt/tinyland-auth` (RS5, RP2).
 *
 * Hard gate, in layers:
 *
 * 1. Compile-time exclusion. This directory is excluded from the production
 *    build (`tsconfig.json`, Bazel `//:tinyland_auth`), so `dist/` and the
 *    published package never contain it. It builds only through
 *    `tsconfig.testing.json` into `dist-testing/`, which is not in `files`.
 * 2. No export. `package.json` has no `./testing` entry under any condition,
 *    so Node and Vite refuse `@tummycrypt/tinyland-auth/testing` with
 *    ERR_PACKAGE_PATH_NOT_EXPORTED. Test suites import the source or the
 *    `dist-testing/` build by path.
 * 3. Load gate. Evaluating this module throws unless `process.env.NODE_ENV`
 *    is exactly `"test"`. Unset, empty, `"production"`, `"development"` and
 *    every other value refuse. There is no caller-supplied environment
 *    anywhere in this module: every check reads the live `process.env`.
 * 4. Admission gate. Minting a user additionally requires
 *    `TINYLAND_AUTH_TEST_ADMISSION=enabled`, read from `process.env` at
 *    construction and on every `admit()`.
 *
 * `scripts/check-production-artifact.mjs` proves layers 1-2 on the real
 * artifact (Bazel `//:pkg` and the npm tarball) with a production Vite
 * bundle; `tests/production-artifact.test.ts` proves layer 3.
 *
 * Production first-admin bootstrap stays the attended `BootstrapService` flow.
 */
import { createHash, randomBytes } from 'crypto';
import {
  installSeams,
  type BackupCodeGenerator,
  type Clock,
} from '../core/seams/index.js';
import { createBackupCodeSet, generateBackupCodes } from '../core/backup-codes/index.js';
import { generateSecurePassword, hashPassword } from '../core/security/password.js';
import { TOTPService, type TOTPServiceConfig } from '../core/totp/index.js';
import { SessionManager, type SessionManagerConfig } from '../core/session/index.js';
import {
  BootstrapService,
  type BootstrapServiceConfig,
} from '../modules/bootstrap/index.js';
import { generateAuthenticatorSecret } from '../totp/otplib-compat.js';
import type { IStorageAdapter } from '../storage/interface.js';
import type {
  AdminUser,
  EncryptedTOTPSecret,
  Session,
  SessionMetadata,
} from '../types/auth.js';
import { ADMIN_ROLES } from '../types/auth.js';

export type { BackupCodeGenerator, Clock };

/**
 * Unique marker compiled into this module and nowhere else. The production
 * artifact check fails if it appears in a production bundle or package.
 */
export const TESTING_ENTRY_SENTINEL = 'tinyland-auth-testing-entry-5a9aa858497cf8b557fcbb77';

/** The only `NODE_ENV` value under which this module loads. */
export const TEST_NODE_ENV = 'test';

/** Environment variable that must also be set to mint users. */
export const TEST_ADMISSION_ENV = 'TINYLAND_AUTH_TEST_ADMISSION';

/** The only value of {@link TEST_ADMISSION_ENV} that opts in. */
export const TEST_ADMISSION_ENV_ENABLED = 'enabled';

export class TestingEntryRefusedError extends Error {
  constructor(reason: string) {
    super(
      `@tummycrypt/tinyland-auth/testing refused to load: ${reason}. ` +
        `It loads only when NODE_ENV is exactly "${TEST_NODE_ENV}". ` +
        // Keeps the sentinel in any bundle that evaluates this module, even a
        // side-effect-only import where the exported constant is tree-shaken.
        `[${TESTING_ENTRY_SENTINEL}]`,
    );
    this.name = 'TestingEntryRefusedError';
  }
}

export class TestAdmissionDisabledError extends Error {
  constructor(reason: string) {
    super(`tinyland-auth test admission is disabled: ${reason}`);
    this.name = 'TestAdmissionDisabledError';
  }
}

/** Reads the live process environment. Deliberately takes no argument. */
function liveEnv(name: string): string | undefined {
  if (typeof process !== 'object' || process === null) return undefined;
  const env = process.env;
  if (typeof env !== 'object' || env === null) return undefined;
  const value = env[name];
  return typeof value === 'string' ? value : undefined;
}

function describeNodeEnv(value: string | undefined): string {
  return value === undefined ? 'NODE_ENV is unset' : `NODE_ENV is ${JSON.stringify(value)}`;
}

/** Throws unless `process.env.NODE_ENV` is exactly `"test"`. */
export function assertTestEnvironment(): void {
  const nodeEnv = liveEnv('NODE_ENV');
  if (nodeEnv !== TEST_NODE_ENV) {
    throw new TestingEntryRefusedError(describeNodeEnv(nodeEnv));
  }
}

// Load gate: runs when this module is evaluated, before any export is usable.
assertTestEnvironment();

/** True only under `NODE_ENV=test` with `TINYLAND_AUTH_TEST_ADMISSION=enabled`. */
export function isTestAdmissionAllowed(): boolean {
  return (
    liveEnv('NODE_ENV') === TEST_NODE_ENV &&
    liveEnv(TEST_ADMISSION_ENV) === TEST_ADMISSION_ENV_ENABLED
  );
}

/** Throws unless {@link isTestAdmissionAllowed}. Reads `process.env` only. */
export function assertTestAdmissionAllowed(): void {
  const nodeEnv = liveEnv('NODE_ENV');
  if (nodeEnv !== TEST_NODE_ENV) {
    throw new TestAdmissionDisabledError(describeNodeEnv(nodeEnv));
  }
  if (liveEnv(TEST_ADMISSION_ENV) !== TEST_ADMISSION_ENV_ENABLED) {
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
 * per-run seed; the codes match the production `XXXX-XXXX` format. The codes
 * are predictable by construction, which is why this lives here only.
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

/**
 * A `TOTPService` whose generation, verification and replay step follow
 * `seams.clock`. Production code cannot construct one: the clock has no
 * public option on `TOTPServiceConfig`.
 */
export function createTestTOTPService(
  config: TOTPServiceConfig,
  seams: { clock: Clock },
): TOTPService {
  assertTestEnvironment();
  const service = new TOTPService(config);
  installSeams(service, { clock: seams.clock });
  return service;
}

/** A `SessionManager` whose own expiry and renewal checks follow `seams.clock`. */
export function createTestSessionManager(
  config: SessionManagerConfig,
  seams: { clock: Clock },
): SessionManager {
  assertTestEnvironment();
  const manager = new SessionManager(config);
  installSeams(manager, { clock: seams.clock });
  return manager;
}

/**
 * A `BootstrapService` with a test clock for the state TTL and/or a
 * deterministic recovery-code generator. For package and harness tests only;
 * production first-admin bootstrap stays attended.
 */
export function createTestBootstrapService(
  config: BootstrapServiceConfig,
  seams: { clock?: Clock; generateBackupCodes?: BackupCodeGenerator },
): BootstrapService {
  assertTestEnvironment();
  const service = new BootstrapService(config);
  installSeams(service, {
    clock: seams.clock,
    generateBackupCodes: seams.generateBackupCodes,
  });
  return service;
}

type AdminRole = AdminUser['role'];

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
  assertTestEnvironment();
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

/**
 * There is intentionally no `env` option: the gate reads `process.env` only
 * (RS5), so configuration can never open it.
 */
export interface TestAdmissionIssuerConfig {
  storage: TestAdmissionStorage;
  /** Same contract as `BootstrapServiceConfig.encryptTOTPSecret`. */
  encryptTOTPSecret: (handle: string, secret: string) => Promise<EncryptedTOTPSecret>;
  bcryptRounds?: number;
  backupCodesCount?: number;
  generateBackupCodes?: BackupCodeGenerator;
  clock?: Clock;
}

export function createTestAdmissionIssuer(config: TestAdmissionIssuerConfig): TestAdmissionIssuer {
  assertTestAdmissionAllowed();

  const nowIso = () => new Date(config.clock ? config.clock.now() : Date.now()).toISOString();

  return {
    async admit(request) {
      assertTestAdmissionAllowed();

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
