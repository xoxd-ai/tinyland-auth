import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as pkg from '../src/index.js';
import {
  BootstrapService,
  MemoryStorageAdapter,
  SessionManager,
  TOTPService,
  type BootstrapServiceConfig,
  type EncryptedTOTPSecret,
  type SessionConfig,
} from '../src/index.js';
import { DEFAULT_BACKUP_CODES_CONFIG } from '../src/core/backup-codes/index.js';
import { generateAuthenticatorSecret, generateAuthenticatorToken } from '../src/totp/otplib-compat.js';
import {
  TEST_ADMISSION_ENV,
  TestAdmissionDisabledError,
  TestingEntryRefusedError,
  assertTestAdmissionAllowed,
  assertTestEnvironment,
  createDeterministicBackupCodeGenerator,
  createManualClock,
  createTestAdmissionIssuer,
  createTestBootstrapService,
  createTestSessionManager,
  createTestTOTPService,
  generateTestIdentity,
  isTestAdmissionAllowed,
  type Clock,
} from '../src/testing/index.js';

const ENCRYPTION_KEY = 'abcdefghijklmnopqrstuvwxyz123456';
const FIXED_EPOCH_MS = Date.UTC(2031, 0, 15, 12, 0, 0);

const totpSecretFor = (secret: string) => ({
  handle: 'seam',
  secret,
  qrCodeUrl: '',
  createdAt: new Date(),
});

const encryptTOTPSecret = async (handle: string, secret: string): Promise<EncryptedTOTPSecret> => ({
  userId: 'pending',
  handle,
  encryptedSecret: `encrypted:${secret.length}`,
  iv: 'iv',
  authTag: 'tag',
  salt: 'salt',
  createdAt: new Date().toISOString(),
  backupCodesGenerated: false,
  version: 1,
});

const bootstrapConfig = (
  storage: MemoryStorageAdapter,
  overrides: Partial<BootstrapServiceConfig> = {},
): BootstrapServiceConfig => ({
  storage,
  appName: 'Seam Test',
  bcryptRounds: 4,
  backupCodesCount: 5,
  generateTOTPSecret: () => generateAuthenticatorSecret(),
  generateQRCode: async () => 'data:image/png;base64,x',
  verifyTOTP: (_secret, token) => token === 'accept',
  encryptTOTPSecret,
  ...overrides,
});

const sessionConfig: SessionConfig = {
  maxAge: 60_000,
  cookieName: 'seam_session',
  secureCookie: false,
  sameSite: 'lax',
  httpOnly: true,
  renewThreshold: 10_000,
  maxConcurrentSessions: 5,
  rememberMeDuration: 120_000,
};

describe('production defaults are unchanged', () => {
  it('exposes no clock, verifier or code-generator seam on the production entry (RS6)', () => {
    const surface = Object.keys(pkg);
    for (const removed of ['systemClock', 'otplibTotpVerifier', 'installSeams', 'seamsOf']) {
      expect(surface).not.toContain(removed);
    }
  });

  it('TOTPService without seams verifies real system-time codes and rejects wrong ones', async () => {
    const service = new TOTPService({ encryptionKey: ENCRYPTION_KEY, issuer: 'Seam' });
    const secret = totpSecretFor(generateAuthenticatorSecret());
    const token = generateAuthenticatorToken(secret.secret);

    expect(service.generateToken(secret)).toBe(token);
    expect(await service.verifyToken(secret, token)).toBe(true);
    const wrong = token === '000000' ? '000001' : '000000';
    expect(await service.verifyToken(secret, wrong)).toBe(false);
    expect(await service.verifyToken(null, token)).toBe(false);

    const step = Math.floor(Date.now() / 1000 / 30);
    const result = await service.verifyTokenWithStep(secret, token);
    expect(result.valid).toBe(true);
    expect(Math.abs((result.step as number) - step)).toBeLessThanOrEqual(1);
    expect(await service.verifyTokenWithStep(secret, token, result.step)).toEqual({ valid: false });
  });

  it('ignores clock, verifier and generator keys passed through production configs', async () => {
    const frozen = createManualClock(Date.UTC(2001, 0, 1));
    const acceptAll = { verify: async () => true, checkDelta: () => 0 };
    const service = new TOTPService({
      encryptionKey: ENCRYPTION_KEY,
      issuer: 'Seam',
      ...({ clock: frozen, verifier: acceptAll } as object),
    });
    const secret = totpSecretFor(generateAuthenticatorSecret());
    const real = generateAuthenticatorToken(secret.secret);
    expect(service.generateToken(secret)).toBe(real);
    expect(await service.verifyToken(secret, real === '123456' ? '654321' : '123456')).toBe(false);

    const storage = new MemoryStorageAdapter();
    await storage.init();
    const bootstrap = new BootstrapService({
      ...bootstrapConfig(storage),
      ...({ clock: frozen, generateBackupCodes: () => ['AAAA-AAAA'] } as object),
    });
    const before = Date.now();
    const { state, backupCodes } = await bootstrap.initiate({
      handle: 'firstadmin',
      password: 'pw-A1!aaaaaaa',
      displayName: 'A',
    });
    expect(state.timestamp).toBeGreaterThanOrEqual(before);
    expect(backupCodes).toHaveLength(5);
    expect(backupCodes).not.toContain('AAAA-AAAA');

    const manager = new SessionManager({
      storage,
      config: sessionConfig,
      ...({ clock: createManualClock(Date.UTC(2100, 0, 1)) } as object),
    });
    const session = await manager.createSession('u1', { handle: 'u1', role: 'member' });
    expect(manager.isSessionValid(session)).toBe(true);
  });

  it('BootstrapService without seams mints random production-format codes and system timestamps', async () => {
    const storage = new MemoryStorageAdapter();
    await storage.init();
    const service = new BootstrapService(bootstrapConfig(storage));
    const before = Date.now();
    const first = await service.initiate({ handle: 'firstadmin', password: 'pw-A1!aaaaaaa', displayName: 'A' });
    const second = await service.initiate({ handle: 'firstadmin', password: 'pw-A1!aaaaaaa', displayName: 'A' });

    expect(first.state.timestamp).toBeGreaterThanOrEqual(before);
    expect(first.state.timestamp).toBeLessThanOrEqual(Date.now());
    expect(first.backupCodes).toHaveLength(5);
    for (const code of first.backupCodes) {
      expect(code).toMatch(DEFAULT_BACKUP_CODES_CONFIG.format);
    }
    expect(first.backupCodes).not.toEqual(second.backupCodes);
    expect(service.isStateValid(first.state)).toBe(true);
  });

  it('SessionManager without a clock treats a fresh session as valid', async () => {
    const storage = new MemoryStorageAdapter();
    await storage.init();
    const manager = new SessionManager({ storage, config: sessionConfig });
    const session = await manager.createSession('u1', { handle: 'u1', role: 'member' });
    expect(manager.isSessionValid(session)).toBe(true);
    expect(await manager.getSession(session.id)).not.toBeNull();
  });
});

describe('test clock through the gated ./testing build', () => {
  it('drives TOTP generation, verification and the replay step from the clock', async () => {
    const clock = createManualClock(FIXED_EPOCH_MS);
    const service = createTestTOTPService({ encryptionKey: ENCRYPTION_KEY, issuer: 'Seam' }, { clock });
    expect(service).toBeInstanceOf(TOTPService);
    const secret = totpSecretFor(generateAuthenticatorSecret());

    const token = service.generateToken(secret);
    expect(token).toBe(generateAuthenticatorToken(secret.secret, FIXED_EPOCH_MS / 1000));

    const first = await service.verifyTokenWithStep(secret, token);
    expect(first).toEqual({ valid: true, step: Math.floor(FIXED_EPOCH_MS / 1000 / 30) });
    expect(await service.verifyTokenWithStep(secret, token, first.step)).toEqual({ valid: false });

    clock.advance(10 * 60 * 1000);
    expect(await service.verifyToken(secret, token)).toBe(false);
    const later = service.generateToken(secret);
    const second = await service.verifyTokenWithStep(secret, later, first.step);
    expect(second.valid).toBe(true);
    expect(second.step).toBe((first.step as number) + 20);
  });

  it('keeps otplib verification: a wrong code fails at the clock time, the unknown-user path too', async () => {
    const clock: Clock = { now: () => FIXED_EPOCH_MS };
    const service = createTestTOTPService({ encryptionKey: ENCRYPTION_KEY, issuer: 'Seam' }, { clock });
    const secret = totpSecretFor(generateAuthenticatorSecret());
    const token = service.generateToken(secret);
    const wrong = token === '000000' ? '000001' : '000000';

    expect(await service.verifyToken(secret, token)).toBe(true);
    expect(await service.verifyToken(secret, wrong)).toBe(false);
    expect(await service.verifyToken(null, token)).toBe(false);
    expect(await service.verifyTokenWithStep(null, token)).toEqual({ valid: false });
  });

  it('expires bootstrap state and sessions when the clock moves', async () => {
    const storage = new MemoryStorageAdapter();
    await storage.init();
    const clock = createManualClock(Date.now());
    const service = createTestBootstrapService(bootstrapConfig(storage), { clock });
    const { state } = await service.initiate({ handle: 'firstadmin', password: 'pw-A1!aaaaaaa', displayName: 'A' });
    expect(state.timestamp).toBe(clock.now());

    clock.advance(10 * 60 * 1000 + 1);
    expect(service.isStateValid(state)).toBe(false);
    expect(await service.complete(state, { handle: 'firstadmin', totpCode: 'accept' })).toEqual({
      success: false,
      error: 'Bootstrap session expired. Please start over.',
    });
    expect(await storage.hasUsers()).toBe(false);

    const manager = createTestSessionManager({ storage, config: sessionConfig }, { clock });
    expect(manager).toBeInstanceOf(SessionManager);
    const session = await manager.createSession('u1', { handle: 'u1', role: 'member' });
    expect(manager.isSessionValid(session)).toBe(true);
    clock.advance(8 * 24 * 60 * 60 * 1000);
    expect(manager.isSessionValid(session)).toBe(false);
  });

  it('attaches seams to the one instance it creates; plain instances keep system time', () => {
    const clock = createManualClock(FIXED_EPOCH_MS);
    const seamed = createTestTOTPService({ encryptionKey: ENCRYPTION_KEY, issuer: 'Seam' }, { clock });
    const plain = new TOTPService({ encryptionKey: ENCRYPTION_KEY, issuer: 'Seam' });
    const secret = totpSecretFor(generateAuthenticatorSecret());
    expect(seamed.generateToken(secret)).toBe(generateAuthenticatorToken(secret.secret, FIXED_EPOCH_MS / 1000));
    expect(plain.generateToken(secret)).toBe(generateAuthenticatorToken(secret.secret));
  });
});

describe('deterministic recovery codes', () => {
  it('is a pure function of the seed, in the production format, with distinct batches', () => {
    const a = createDeterministicBackupCodeGenerator('run-1');
    const b = createDeterministicBackupCodeGenerator('run-1');
    const c = createDeterministicBackupCodeGenerator('run-2');
    const firstBatch = a(6);

    expect(firstBatch).toEqual(b(6));
    expect(firstBatch).not.toEqual(c(6));
    expect(a(6)).not.toEqual(firstBatch);
    expect(new Set(firstBatch).size).toBe(6);
    for (const code of firstBatch) {
      expect(code).toMatch(DEFAULT_BACKUP_CODES_CONFIG.format);
    }
    expect(() => createDeterministicBackupCodeGenerator('')).toThrow();
  });

  it('is used by BootstrapService only when injected', async () => {
    const storage = new MemoryStorageAdapter();
    await storage.init();
    const service = createTestBootstrapService(bootstrapConfig(storage), {
      generateBackupCodes: createDeterministicBackupCodeGenerator('run-1'),
    });
    const { state, backupCodes } = await service.initiate({
      handle: 'firstadmin',
      password: 'pw-A1!aaaaaaa',
      displayName: 'A',
    });
    expect(backupCodes).toEqual(createDeterministicBackupCodeGenerator('run-1')(5));

    const completed = await service.complete(state, { handle: 'firstadmin', totpCode: 'accept' });
    expect(completed.success).toBe(true);
    expect(completed.backupCodes).toEqual(backupCodes);
  });
});

describe('test admission issuer', () => {
  // RS5: the gate reads only the live process.env. Tests drive it through
  // vi.stubEnv, which writes process.env, never through a config object.
  beforeEach(() => {
    vi.stubEnv('NODE_ENV', 'test');
    vi.stubEnv(TEST_ADMISSION_ENV, 'enabled');
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('fails closed unless NODE_ENV is exactly "test" and the opt-in is set', () => {
    expect(isTestAdmissionAllowed()).toBe(true);
    expect(() => assertTestAdmissionAllowed()).not.toThrow();

    for (const value of ['1', 'true', 'ENABLED', '']) {
      vi.stubEnv(TEST_ADMISSION_ENV, value);
      expect(isTestAdmissionAllowed()).toBe(false);
      expect(() => assertTestAdmissionAllowed()).toThrow(TestAdmissionDisabledError);
    }
    vi.stubEnv(TEST_ADMISSION_ENV, undefined);
    expect(() => assertTestAdmissionAllowed()).toThrow(/TINYLAND_AUTH_TEST_ADMISSION is not "enabled"/);

    vi.stubEnv(TEST_ADMISSION_ENV, 'enabled');
    for (const nodeEnv of ['production', 'development', 'TEST', '']) {
      vi.stubEnv('NODE_ENV', nodeEnv);
      expect(isTestAdmissionAllowed()).toBe(false);
      expect(() => assertTestAdmissionAllowed()).toThrow(TestAdmissionDisabledError);
      expect(() => assertTestEnvironment()).toThrow(TestingEntryRefusedError);
    }
    vi.stubEnv('NODE_ENV', undefined);
    expect(() => assertTestAdmissionAllowed()).toThrow(/NODE_ENV is unset/);
    expect(() => assertTestEnvironment()).toThrow(/NODE_ENV is unset/);
  });

  it('takes no caller-supplied environment: an env option cannot open the gate', async () => {
    const storage = new MemoryStorageAdapter();
    await storage.init();
    vi.stubEnv(TEST_ADMISSION_ENV, undefined);
    const smuggled = { env: { NODE_ENV: 'test', [TEST_ADMISSION_ENV]: 'enabled' } } as object;
    expect(() => createTestAdmissionIssuer({ storage, encryptTOTPSecret, ...smuggled })).toThrow(
      TestAdmissionDisabledError,
    );
    expect(isTestAdmissionAllowed.length).toBe(0);
    expect(assertTestAdmissionAllowed.length).toBe(0);
    expect(assertTestEnvironment.length).toBe(0);
  });

  it('re-checks process.env on every admit()', async () => {
    const storage = new MemoryStorageAdapter();
    await storage.init();
    const issuer = createTestAdmissionIssuer({ storage, encryptTOTPSecret });
    vi.stubEnv('NODE_ENV', 'production');
    await expect(issuer.admit({ role: 'member' })).rejects.toBeInstanceOf(TestAdmissionDisabledError);
    vi.stubEnv('NODE_ENV', 'test');
    vi.stubEnv(TEST_ADMISSION_ENV, undefined);
    await expect(issuer.admit({ role: 'member' })).rejects.toBeInstanceOf(TestAdmissionDisabledError);
    expect(await storage.hasUsers()).toBe(false);
  });

  it('refuses seam factories once NODE_ENV leaves "test"', () => {
    vi.stubEnv('NODE_ENV', 'production');
    const clock = createManualClock(0);
    expect(() => createTestTOTPService({ encryptionKey: ENCRYPTION_KEY, issuer: 'Seam' }, { clock })).toThrow(
      TestingEntryRefusedError,
    );
    expect(() => generateTestIdentity('member')).toThrow(TestingEntryRefusedError);
  });

  it('admits a generated identity at every role with working credentials', async () => {
    const storage = new MemoryStorageAdapter();
    await storage.init();
    const issuer = createTestAdmissionIssuer({
      storage,
      encryptTOTPSecret,
      backupCodesCount: 3,
      generateBackupCodes: createDeterministicBackupCodeGenerator('admission'),
    });
    const totp = new TOTPService({ encryptionKey: ENCRYPTION_KEY, issuer: 'Seam' });

    const roles = ['super_admin', 'admin', 'moderator', 'editor', 'contributor', 'member', 'viewer'] as const;
    const handles = new Set<string>();
    for (const role of roles) {
      const admission = await issuer.admit({ role });
      handles.add(admission.identity.handle);

      expect(admission.user.role).toBe(role);
      expect(admission.user).not.toHaveProperty('passwordHash');
      expect(admission.identity.handle).toMatch(/^[a-zA-Z][a-zA-Z0-9_-]{2,29}$/);
      expect(admission.identity.email.endsWith('.test')).toBe(true);
      expect(admission.backupCodes).toHaveLength(3);
      expect(admission.session?.userId).toBe(admission.user.id);
      expect(admission.session?.user?.role).toBe(role);

      const stored = await storage.getUserByHandle(admission.identity.handle);
      expect(stored?.passwordHash).toBeTruthy();
      expect(stored?.passwordHash).not.toContain(admission.identity.password);
      expect(await storage.getTOTPSecret(admission.identity.handle)).not.toBeNull();
      expect((await storage.getBackupCodes(admission.user.id))?.codes).toHaveLength(3);

      const secret = totpSecretFor(admission.identity.totpSecret);
      expect(await totp.verifyToken(secret, totp.generateToken(secret))).toBe(true);
    }
    expect(handles.size).toBe(roles.length);

    const events = await storage.getRecentAuditEvents(50);
    expect(events.filter((event) => (event.type as string) === 'TEST_ADMISSION')).toHaveLength(roles.length);
  });

  it('generates distinct identities per call and rejects mismatches and duplicates', async () => {
    const one = generateTestIdentity('moderator', { runId: 'r1' });
    const two = generateTestIdentity('moderator', { runId: 'r1' });
    expect(one.handle).not.toBe(two.handle);
    expect(one.password).not.toBe(two.password);
    expect(one.totpSecret).not.toBe(two.totpSecret);
    expect(() => generateTestIdentity('root' as never)).toThrow(/Unknown role/);

    const storage = new MemoryStorageAdapter();
    await storage.init();
    const issuer = createTestAdmissionIssuer({ storage, encryptTOTPSecret });
    await expect(issuer.admit({ role: 'admin', identity: one })).rejects.toThrow(/does not match/);
    const admitted = await issuer.admit({ role: 'moderator', identity: one, createSession: false });
    expect(admitted.session).toBeUndefined();
    await expect(issuer.admit({ role: 'moderator', identity: one })).rejects.toThrow(/already exists/);
  });
});
