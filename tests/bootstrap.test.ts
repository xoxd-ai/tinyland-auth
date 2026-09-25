import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  BootstrapService,
  MemoryBootstrapAttemptStore,
  createBootstrapService,
  runBootstrapAttemptStoreConformance,
  type BootstrapServiceConfig,
  type BootstrapState,
} from '../src/modules/bootstrap/index.js';
import { MemoryStorageAdapter } from '../src/storage/memory.js';
import type { EncryptedTOTPSecret } from '../src/types/auth.js';

const TENANT_ID = '12345678-1234-4123-8123-123456789abc';
const mockGenerateTOTPSecret = () => 'MOCK_SECRET_BASE32';
const mockGenerateQRCode = async () => 'data:image/png;base64,mockqrcode';
const mockVerifyTOTP = (_secret: string, token: string) => token === '123456';
const mockEncryptTOTPSecret = async (
  handle: string,
  secret: string,
): Promise<EncryptedTOTPSecret> => ({
  userId: 'pending',
  handle,
  encryptedSecret: `encrypted:${secret}`,
  iv: 'mock-iv',
  authTag: 'mock-tag',
  salt: 'mock-salt',
  createdAt: new Date().toISOString(),
  backupCodesGenerated: false,
  version: 1,
});
const mockDecryptTOTPSecret = async (secret: EncryptedTOTPSecret) =>
  secret.encryptedSecret.replace(/^encrypted:/, '');

describe('BootstrapService atomic first-user flow', () => {
  let storage: MemoryStorageAdapter;
  let attemptStore: MemoryBootstrapAttemptStore;
  let config: BootstrapServiceConfig;
  let service: BootstrapService;
  let nowMs: number;

  beforeEach(async () => {
    storage = new MemoryStorageAdapter();
    nowMs = Date.now();
    attemptStore = new MemoryBootstrapAttemptStore(() => new Date(nowMs));
    await storage.init();
    config = {
      storage,
      attemptStore,
      tenantId: TENANT_ID,
      appName: 'Test App',
      bcryptRounds: 4,
      backupCodesCount: 5,
      generateTOTPSecret: mockGenerateTOTPSecret,
      generateQRCode: mockGenerateQRCode,
      verifyTOTP: mockVerifyTOTP,
      encryptTOTPSecret: mockEncryptTOTPSecret,
      decryptTOTPSecret: mockDecryptTOTPSecret,
      now: () => new Date(nowMs),
    };
    service = new BootstrapService(config);
  });

  async function initiate(): Promise<{
    state: BootstrapState;
    backupCodes: string[];
  }> {
    return service.initiate({
      handle: 'admin',
      password: 'SecurePassword123!',
      displayName: 'Admin User',
      email: 'admin@test.com',
    });
  }

  async function complete(state: BootstrapState, totpCode = '123456') {
    return service.complete(state, { handle: 'admin', totpCode });
  }

  it('reports an empty store as bootstrapable but not configured', async () => {
    await expect(service.getStatus()).resolves.toEqual({
      needsBootstrap: true,
      hasUsers: false,
      systemConfigured: false,
    });
  });

  it('returns only opaque browser state and keeps credentials server-side', async () => {
    const result = await initiate();
    expect(result.state).toEqual({ version: 1, attemptId: expect.any(String) });
    expect(Object.keys(result.state).sort()).toEqual(['attemptId', 'version']);
    expect(JSON.stringify(result.state)).not.toMatch(/password|secret|backup|handle|email/i);
    expect(result.backupCodes).toHaveLength(5);

    const pending = await attemptStore.get(TENANT_ID, result.state.attemptId);
    expect(pending?.handle).toBe('admin');
    expect(pending?.passwordHash).toMatch(/^\$2[aby]\$/);
    expect(pending?.totpSecret).toBe('MOCK_SECRET_BASE32');
    expect(pending?.backupCodes).toEqual(result.backupCodes);
    await expect(service.getStatus()).resolves.toEqual({
      needsBootstrap: false,
      hasUsers: false,
      systemConfigured: false,
    });
  });

  it('does not put browser fingerprint or Tempo evidence into bootstrap authority', async () => {
    const result = await service.initiate({
      handle: 'admin',
      password: 'SecurePassword123!',
      displayName: 'Admin User',
      browserFingerprint: 'browser-evidence-only',
      tempoTraceId: 'tempo-evidence-only',
    } as Parameters<BootstrapService['initiate']>[0] & {
      browserFingerprint: string;
      tempoTraceId: string;
    });
    const pending = await attemptStore.get(TENANT_ID, result.state.attemptId);
    expect(pending).not.toHaveProperty('browserFingerprint');
    expect(pending).not.toHaveProperty('tempoTraceId');
    const completed = await complete(result.state);
    expect(completed.success).toBe(true);
    expect(completed.user).not.toHaveProperty('browserFingerprint');
    expect(completed.user).not.toHaveProperty('tempoTraceId');
  });

  it('canonicalizes optional profile strings before attempt custody', async () => {
    const result = await service.initiate({
      handle: 'admin',
      password: 'SecurePassword123!',
      displayName: '  Admin User  ',
      email: '  ADMIN@TEST.COM  ',
    });
    const pending = await attemptStore.get(TENANT_ID, result.state.attemptId);
    expect(pending).toMatchObject({
      displayName: 'Admin User',
      email: 'admin@test.com',
    });
    const completed = await service.complete(result.state, {
      handle: 'admin',
      totpCode: '123456',
    });
    expect(completed.user).toMatchObject({ email: 'admin@test.com' });
  });

  it('rejects invalid handles and existing users', async () => {
    await expect(
      service.initiate({
        handle: '123invalid',
        password: 'test',
        displayName: 'Test',
      }),
    ).rejects.toThrow('Handle must start with a letter');

    vi.spyOn(storage, 'hasUsers').mockResolvedValue(true);
    await expect(initiate()).rejects.toThrow('Bootstrap not allowed');
  });

  it('allows exactly one concurrent first-user claim', async () => {
    const second = new BootstrapService(config);
    const request = {
      handle: 'admin',
      password: 'SecurePassword123!',
      displayName: 'Admin User',
    };
    const results = await Promise.allSettled([
      service.initiate(request),
      second.initiate(request),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
  });

  it('atomically allows one active attempt in the single-process store', async () => {
    const { state } = await initiate();
    const pending = await attemptStore.get(TENANT_ID, state.attemptId);
    expect(pending).not.toBeNull();

    const isolatedStore = new MemoryBootstrapAttemptStore(() => new Date(nowMs));
    const results = await Promise.allSettled([
      isolatedStore.create(structuredClone(pending!)),
      isolatedStore.create({
        ...structuredClone(pending!),
        attemptId: 'second-attempt-identifier-0002',
        actorId: 'second-actor',
      }),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
  });

  it('rejects weak custom attempt identifiers before generating credentials', async () => {
    const weak = new BootstrapService({
      ...config,
      generateAttemptId: () => 'predictable',
    });
    await expect(weak.initiate({
      handle: 'admin',
      password: 'SecurePassword123!',
      displayName: 'Admin User',
    })).rejects.toThrow(/attempt ids must be opaque/i);
    expect(await attemptStore.getActiveForTenant(TENANT_ID)).toBeNull();
  });

  it('rejects a service lifetime different from the storage claim window', () => {
    expect(() => new BootstrapService({
      ...config,
      maxAgeMs: 10 * 60 * 1000 + 1,
    })).toThrow(/must equal the storage claim window/i);
    expect(() => new BootstrapService({
      ...config,
      maxAgeMs: 5 * 60 * 1000,
    })).toThrow(/must equal the storage claim window/i);
  });

  it('stores profile updates server-side before finalization', async () => {
    const { state } = await initiate();
    expect(await service.updateProfile(state, {
      bio: 'System administrator',
      pronouns: 'they/them',
    })).toEqual(state);
    expect((await attemptStore.get(TENANT_ID, state.attemptId))?.profile).toEqual({
      bio: 'System administrator',
      pronouns: 'they/them',
    });
    const result = await complete(state);
    expect(result.user?.bio).toBe('System administrator');
    expect(result.user?.pronouns).toBe('they/them');
  });

  it('atomically creates the user, factors, receipt, and audit', async () => {
    const { state } = await initiate();
    const result = await complete(state);
    expect(result.success).toBe(true);
    expect(result.user?.handle).toBe('admin');
    expect(result.user?.role).toBe('super_admin');
    expect(result.user).not.toHaveProperty('passwordHash');
    expect(result.backupCodes).toBeUndefined();

    const user = await storage.getUserByHandle('admin');
    expect(user?.totpEnabled).toBe(true);
    expect((await storage.getTOTPSecret('admin'))?.userId).toBe(user?.id);
    expect((await storage.getBackupCodes(user!.id))?.codes).toHaveLength(5);
    expect(await storage.getFirstUserBootstrapReceipt(TENANT_ID)).not.toBeNull();
    expect((await storage.getRecentAuditEvents(10)).some(
      (event) => event.type === 'BOOTSTRAP_COMPLETED',
    )).toBe(true);
    expect(await attemptStore.get(TENANT_ID, state.attemptId)).toBeNull();
  });

  it('requires finalized authority metadata, decryptability, and backup codes', async () => {
    const { state } = await initiate();
    const result = await complete(state);
    expect(result.success).toBe(true);
    expect((await service.getStatus()).systemConfigured).toBe(true);
    await storage.updateUser(result.user!.id, { isActive: false });
    const degraded = await service.getStatus();
    expect(degraded.needsBootstrap).toBe(false);
    expect(degraded.systemConfigured).toBe(false);
  });

  it('requires encrypted TOTP material to round-trip before finalization', async () => {
    const invalidEncryption = new BootstrapService({
      ...config,
      decryptTOTPSecret: async () => 'different-secret',
    });
    const { state } = await invalidEncryption.initiate({
      handle: 'admin',
      password: 'SecurePassword123!',
      displayName: 'Admin User',
    });
    await expect(invalidEncryption.complete(state, {
      handle: 'admin',
      totpCode: '123456',
    })).resolves.toMatchObject({
      success: false,
      error: expect.stringMatching(/round-trip validation failed/i),
    });
    expect(await storage.hasUsers()).toBe(false);
    expect(await storage.getFirstUserBootstrapReceipt(TENANT_ID)).toBeNull();
  });

  it('reports finalized authority unhealthy when its TOTP cannot be decrypted', async () => {
    const { state } = await initiate();
    expect((await complete(state)).success).toBe(true);
    const wrongKey = new BootstrapService({
      ...config,
      decryptTOTPSecret: async () => {
        throw new Error('wrong key');
      },
    });
    await expect(wrongKey.getStatus()).resolves.toMatchObject({
      needsBootstrap: false,
      hasUsers: true,
      systemConfigured: false,
    });
  });

  it('leaves an invalid-TOTP claim inert', async () => {
    const { state } = await initiate();
    const result = await complete(state, '000000');
    expect(result.success).toBe(false);
    expect(result.error).toContain('Invalid TOTP code');
    expect(await storage.hasUsers()).toBe(false);
    expect(await storage.getTOTPSecret('admin')).toBeNull();
    expect(await storage.getFirstUserBootstrapReceipt(TENANT_ID)).toBeNull();
  });

  it('awaits an asynchronous TOTP rejection without finalizing authority', async () => {
    const asyncVerifier = new BootstrapService({
      ...config,
      verifyTOTP: async () => false,
    });
    const { state } = await asyncVerifier.initiate({
      handle: 'admin',
      password: 'SecurePassword123!',
      displayName: 'Admin User',
    });

    await expect(asyncVerifier.complete(state, {
      handle: 'admin',
      totpCode: '123456',
    })).resolves.toMatchObject({
      success: false,
      error: expect.stringMatching(/invalid TOTP code/i),
    });
    expect(await storage.hasUsers()).toBe(false);
    expect(await storage.getTOTPSecret('admin')).toBeNull();
    expect(await storage.getFirstUserBootstrapReceipt(TENANT_ID)).toBeNull();
  });

  it('accepts asynchronous and synchronous TOTP verifiers only when they return true', async () => {
    const asyncVerifier = new BootstrapService({
      ...config,
      verifyTOTP: async () => true,
    });
    const { state } = await asyncVerifier.initiate({
      handle: 'admin',
      password: 'SecurePassword123!',
      displayName: 'Admin User',
    });
    await expect(asyncVerifier.complete(state, {
      handle: 'admin',
      totpCode: '123456',
    })).resolves.toMatchObject({
      success: true,
      user: expect.objectContaining({ role: 'super_admin' }),
    });

    await storage.close();
    storage = new MemoryStorageAdapter();
    await storage.init();
    attemptStore = new MemoryBootstrapAttemptStore(() => new Date(nowMs));
    const syncVerifier = new BootstrapService({
      ...config,
      storage,
      attemptStore,
      verifyTOTP: () => true,
    });
    const second = await syncVerifier.initiate({
      handle: 'admin',
      password: 'SecurePassword123!',
      displayName: 'Admin User',
    });
    await expect(syncVerifier.complete(second.state, {
      handle: 'admin',
      totpCode: '123456',
    })).resolves.toMatchObject({ success: true });
  });

  it('fails closed when an asynchronous TOTP verifier rejects', async () => {
    const rejectingVerifier = new BootstrapService({
      ...config,
      verifyTOTP: async () => {
        throw new Error('TOTP verifier unavailable');
      },
    });
    const { state } = await rejectingVerifier.initiate({
      handle: 'admin',
      password: 'SecurePassword123!',
      displayName: 'Admin User',
    });

    await expect(rejectingVerifier.complete(state, {
      handle: 'admin',
      totpCode: '123456',
    })).resolves.toEqual({
      success: false,
      error: 'TOTP verifier unavailable',
    });
    expect(await storage.hasUsers()).toBe(false);
    expect(await storage.getTOTPSecret('admin')).toBeNull();
    expect(await storage.getFirstUserBootstrapReceipt(TENANT_ID)).toBeNull();
  });

  it('fails closed for forged state, mismatch, and isolated custody', async () => {
    const { state } = await initiate();
    await expect(service.complete(
      { version: 1, attemptId: 'forged-attempt' },
      { handle: 'admin', totpCode: '123456' },
    )).resolves.toMatchObject({ success: false, error: expect.stringMatching(/invalid/i) });
    await expect(service.complete(
      state,
      { handle: 'different', totpCode: '123456' },
    )).resolves.toEqual({ success: false, error: 'Handle mismatch' });

    const isolated = new BootstrapService({
      ...config,
      attemptStore: new MemoryBootstrapAttemptStore(),
    });
    await expect(isolated.complete(
      state,
      { handle: 'admin', totpCode: '123456' },
    )).resolves.toMatchObject({ success: false, error: expect.stringMatching(/invalid/i) });
  });

  it('rejects an unverified expired attempt', async () => {
    const { state } = await initiate();
    nowMs += 11 * 60 * 1000;
    await expect(complete(state)).resolves.toMatchObject({
      success: false,
      error: expect.stringMatching(/expired/i),
    });
    expect(await storage.hasUsers()).toBe(false);
  });

  it.each([
    [599_999, true],
    [600_000, true],
    [600_001, false],
  ])('uses the inclusive completion lifetime at %i ms', async (ageMs, expected) => {
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      const startedAt = nowMs;
      vi.setSystemTime(startedAt);
      const { state } = await initiate();
      nowMs = startedAt + ageMs;
      vi.setSystemTime(nowMs);

      const result = await complete(state);
      expect(result.success).toBe(expected);
      expect(await storage.hasUsers()).toBe(expected);
      if (expected) {
        expect(result.user).toMatchObject({ role: 'super_admin' });
      } else {
        expect(result.error).toMatch(/expired/i);
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it('makes concurrent exact completion idempotent', async () => {
    const { state } = await initiate();
    const [first, second] = await Promise.all([complete(state), complete(state)]);
    expect(first.success).toBe(true);
    expect(second.success).toBe(true);
    expect(first.user).toEqual(second.user);
    expect(first.backupCodes).toBeUndefined();
    expect(second.backupCodes).toBeUndefined();
    expect(await storage.getAllUsers()).toHaveLength(1);
  });

  it('replays a delayed exact completion after its attempt is deleted', async () => {
    let encryptionStarted!: () => void;
    let releaseEncryption!: () => void;
    const started = new Promise<void>((resolve) => {
      encryptionStarted = resolve;
    });
    const encryptionGate = new Promise<void>((resolve) => {
      releaseEncryption = resolve;
    });
    const delayed = new BootstrapService({
      ...config,
      encryptTOTPSecret: async (handle, secret) => {
        encryptionStarted();
        await encryptionGate;
        return mockEncryptTOTPSecret(handle, secret);
      },
    });
    const { state } = await delayed.initiate({
      handle: 'admin',
      password: 'SecurePassword123!',
      displayName: 'Admin User',
    });

    const delayedCompletion = delayed.complete(state, {
      handle: 'admin',
      totpCode: '123456',
    });
    await started;
    const winner = await complete(state);
    expect(winner.success).toBe(true);
    expect(await attemptStore.get(TENANT_ID, state.attemptId)).toBeNull();

    releaseEncryption();
    await expect(delayedCompletion).resolves.toEqual(winner);
  });

  it('rejects stale profile finalization and succeeds from a fresh snapshot', async () => {
    let releaseEncryption!: () => void;
    let encryptionStarted!: () => void;
    const encryptionGate = new Promise<void>((resolve) => {
      releaseEncryption = resolve;
    });
    const started = new Promise<void>((resolve) => {
      encryptionStarted = resolve;
    });
    const racing = new BootstrapService({
      ...config,
      encryptTOTPSecret: async (handle, secret) => {
        encryptionStarted();
        await encryptionGate;
        return mockEncryptTOTPSecret(handle, secret);
      },
    });
    const startedAttempt = await racing.initiate({
      handle: 'admin',
      password: 'SecurePassword123!',
      displayName: 'Admin User',
    });
    const firstCompletion = racing.complete(startedAttempt.state, {
      handle: 'admin',
      totpCode: '123456',
    });
    await started;
    await racing.updateProfile(startedAttempt.state, { bio: 'Latest profile' });
    releaseEncryption();

    await expect(firstCompletion).resolves.toMatchObject({
      success: false,
      error: expect.stringMatching(/changed while finalization/i),
    });
    const retried = await racing.complete(startedAttempt.state, {
      handle: 'admin',
      totpCode: '123456',
    });
    expect(retried.success).toBe(true);
    expect(retried.user?.bio).toBe('Latest profile');
  });

  it('expires a prepared but uncommitted attempt instead of wedging bootstrap', async () => {
    const originalFinalize = storage.finalizeFirstUserBootstrap.bind(storage);
    let failFinalization = true;
    storage.finalizeFirstUserBootstrap = async (finalization) => {
      if (failFinalization) throw new Error('storage unavailable');
      return originalFinalize(finalization);
    };
    const { state } = await initiate();
    await expect(complete(state)).resolves.toMatchObject({
      success: false,
      error: 'storage unavailable',
    });
    expect((await attemptStore.get(TENANT_ID, state.attemptId))?.finalization)
      .toBeDefined();

    nowMs += 11 * 60 * 1000;
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      vi.setSystemTime(nowMs);
      await expect(service.isStateValid(state)).resolves.toBe(false);
      expect(await attemptStore.getActiveForTenant(TENANT_ID)).toBeNull();
      failFinalization = false;
      await expect(initiate()).resolves.toMatchObject({
        state: { version: 1, attemptId: expect.any(String) },
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it('replays a committed lost response before expiry and TOTP checks', async () => {
    const { state } = await initiate();
    const first = await complete(state);
    expect(first.success).toBe(true);
    nowMs += 60 * 60 * 1000;
    const replay = await complete(state, 'expired-code');
    expect(replay.success).toBe(true);
    expect(replay.user).toEqual(first.user);
    expect(replay.backupCodes).toBeUndefined();

    expect(await service.complete(
      { version: 1, attemptId: 'different-attempt-identifier-0002' },
      { handle: 'admin', totpCode: '123456' },
    )).toEqual({
      success: false,
      error: 'Bootstrap was finalized by a different attempt',
    });
  });

  it('never re-discloses pending credentials when receipt cleanup fails', async () => {
    const stickyStore = new MemoryBootstrapAttemptStore(() => new Date(nowMs));
    const sticky = new BootstrapService({ ...config, attemptStore: stickyStore });
    const started = await sticky.initiate({
      handle: 'admin',
      password: 'SecurePassword123!',
      displayName: 'Admin User',
    });
    stickyStore.delete = async () => {
      throw new Error('cleanup unavailable');
    };
    const first = await sticky.complete(started.state, {
      handle: 'admin',
      totpCode: '123456',
    });
    expect(first.success).toBe(true);
    expect(first.backupCodes).toBeUndefined();
    const replay = await sticky.complete(started.state, {
      handle: 'admin',
      totpCode: '000000',
    });
    expect(replay.success).toBe(true);
    expect(replay.backupCodes).toBeUndefined();
  });

  it('does not report authority failure when secondary audit IO fails', async () => {
    const { state } = await initiate();
    storage.logAuditEvent = async () => {
      throw new Error('audit unavailable');
    };
    expect((await complete(state)).success).toBe(true);
    expect(await storage.getFirstUserBootstrapReceipt(TENANT_ID)).not.toBeNull();
  });

  it('blocks ordinary creation before any bootstrap claim exists', async () => {
    const timestamp = new Date().toISOString();
    await expect(storage.createUser({
      handle: 'bypass',
      passwordHash: 'hash',
      role: 'super_admin',
      isActive: true,
      totpEnabled: false,
      needsOnboarding: false,
      onboardingStep: 0,
      createdAt: timestamp,
      updatedAt: timestamp,
    })).rejects.toThrow(/finalized first-user bootstrap receipt/i);
    expect(await storage.hasUsers()).toBe(false);
  });

  it('blocks ordinary creation while the inert claim is active', async () => {
    await initiate();
    const timestamp = new Date().toISOString();
    await expect(storage.createUser({
      handle: 'bypass',
      passwordHash: 'hash',
      role: 'super_admin',
      isActive: true,
      totpEnabled: false,
      needsOnboarding: false,
      onboardingStep: 0,
      createdAt: timestamp,
      updatedAt: timestamp,
    })).rejects.toThrow(/claim is active/);
  });

  it('validates state through server custody, not client timestamps', async () => {
    const startedAt = nowMs;
    const { state } = await initiate();
    await expect(service.isStateValid({ version: 1, attemptId: 'unknown' })).resolves.toBe(false);

    nowMs = startedAt + 599_999;
    await expect(service.isStateValid(state)).resolves.toBe(true);
    nowMs = startedAt + 600_000;
    await expect(service.isStateValid(state)).resolves.toBe(true);
    nowMs = startedAt + 600_001;
    await expect(service.isStateValid(state)).resolves.toBe(false);
  });

  it('createBootstrapService creates the hardened service', () => {
    expect(createBootstrapService(config)).toBeInstanceOf(BootstrapService);
  });

  it('passes the reusable attempt-store conformance contract', async () => {
    const harnessOrigin = Date.parse('2041-02-03T04:05:06.000Z');
    const results = await runBootstrapAttemptStoreConformance(async () => {
      let conformanceNow = harnessOrigin;
      return {
        store: new MemoryBootstrapAttemptStore(
          () => new Date(conformanceNow),
        ),
        now: () => new Date(conformanceNow),
        advanceTime: async (ms) => {
          conformanceNow += ms;
        },
        cleanup: async () => undefined,
      };
    });
    expect(results).toHaveLength(9);
  });
});
