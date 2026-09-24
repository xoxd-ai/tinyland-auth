import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { hashBackupCode } from '../src/core/backup-codes/index.js';
import {
  FileTotpEnrollmentCoordinator,
  type FileTotpEnrollmentConfig,
  type TotpEnrollmentBinding,
  type TotpEnrollmentCompletion,
  type TotpEnrollmentCurrentState,
  type TotpEnrollmentSetup,
  type TotpEnrollmentRequest,
  type PrimaryReauthAuthorization,
} from '../src/storage/file-totp-enrollment.js';
import type { AdminUser, EncryptedData, TOTPSecret } from '../src/types/auth.js';

const START = Date.parse('2026-09-19T12:00:00.000Z');
const TOKEN = '385729';
const VERIFIED_STEP = 59_660_401;
const ownedDirectories: string[] = [];

function copy<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

async function fixture() {
  const directory = await fs.mkdtemp(path.join(tmpdir(), 'tinyland-auth-enrollment-'));
  ownedDirectories.push(directory);
  let clock = START;
  const binding: TotpEnrollmentBinding = {
    userId: 'member:legacy-id/alice',
    sessionId: 'session:initiating-private-bearer',
  };
  const user: AdminUser = {
    id: binding.userId,
    handle: 'alice',
    displayName: 'Alice Example',
    passwordHash: 'existing-password-hash',
    role: 'member',
    permissions: ['existing:capability'],
    isActive: true,
    needsOnboarding: true,
    onboardingStep: 1,
    totpEnabled: false,
    createdAt: new Date(START - 60_000).toISOString(),
    updatedAt: new Date(START - 60_000).toISOString(),
    bio: 'Existing profile must survive enrollment.',
  };
  const state: TotpEnrollmentCurrentState = {
    user,
    session: {
      id: binding.sessionId,
      userId: binding.userId,
      expires: new Date(START + 86_400_000).toISOString(),
      expiresAt: new Date(START + 86_400_000).toISOString(),
      createdAt: new Date(START).toISOString(),
      clientIp: '127.0.0.1',
      userAgent: 'enrollment-regression-test',
      user: {
        id: binding.userId,
        username: user.handle,
        name: user.displayName!,
        role: user.role,
        needsOnboarding: true,
        onboardingStep: 1,
      },
    },
    totpSecret: null,
    backupCodes: null,
  };

  // Fast authenticated encryption keeps these storage tests independent of
  // production scrypt/TOTP timing. Primitive compatibility has its own tests.
  const encryptionKey = randomBytes(32);
  const totp = {
    generateSecret: vi.fn(async (handle: string): Promise<TOTPSecret> => ({
      handle,
      secret: `TEST-SECRET-${randomBytes(24).toString('hex')}`,
      createdAt: new Date(clock),
    })),
    generateQRCode: vi.fn(async (secret: TOTPSecret) => `data:test-qr,${secret.handle}:${secret.secret}`),
    encrypt: vi.fn((plaintext: string): EncryptedData => {
      const iv = randomBytes(12);
      const salt = randomBytes(16);
      const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);
      cipher.setAAD(salt);
      const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      return {
        encrypted: encrypted.toString('base64'),
        iv: iv.toString('base64'),
        salt: salt.toString('base64'),
        tag: cipher.getAuthTag().toString('base64'),
      };
    }),
    decrypt: vi.fn((value: EncryptedData): string => {
      const decipher = createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(value.iv, 'base64'));
      decipher.setAAD(Buffer.from(value.salt, 'base64'));
      decipher.setAuthTag(Buffer.from(value.tag, 'base64'));
      return Buffer.concat([
        decipher.update(Buffer.from(value.encrypted, 'base64')),
        decipher.final(),
      ]).toString('utf8');
    }),
    verifyTokenWithStep: vi.fn(async (_secret: TOTPSecret | null, token: string): Promise<{ valid: boolean; step?: number }> => (
      token.replace(/\s/g, '') === TOKEN ? { valid: true, step: VERIFIED_STEP } : { valid: false }
    )),
  } satisfies FileTotpEnrollmentConfig['totp'];

  const loadCurrent = vi.fn(async (requested: TotpEnrollmentBinding): Promise<TotpEnrollmentCurrentState> => ({
    user: state.user?.id === requested.userId ? copy(state.user) : null,
    session: state.session?.id === requested.sessionId ? copy(state.session) : null,
    totpSecret: copy(state.totpSecret),
    backupCodes: copy(state.backupCodes),
  }));
  const applyProjection = async (completion: TotpEnrollmentCompletion): Promise<void> => {
    state.totpSecret = copy(completion.totpSecret);
    state.backupCodes = copy(completion.backupCodes);
    Object.assign(state.user!, copy(completion.userPatch));
  };
  const project = vi.fn(applyProjection);
  const config: FileTotpEnrollmentConfig = {
    directory,
    totp,
    loadCurrent,
    project,
    ttlMs: 60_000,
    now: () => new Date(clock),
  };
  const coordinator = new FileTotpEnrollmentCoordinator(config);
  const filename = path.join(directory, `${createHash('sha256').update(binding.userId).digest('hex')}.json`);
  return {
    directory, filename, binding, state, totp, project, loadCurrent, applyProjection, coordinator,
    fresh: (overrides: Partial<FileTotpEnrollmentConfig> = {}) => new FileTotpEnrollmentCoordinator({ ...config, ...overrides }),
    setTime: (milliseconds: number) => { clock = milliseconds; },
    readRecord: async <T = Record<string, unknown>>(): Promise<T> => JSON.parse(await fs.readFile(filename, 'utf8')) as T,
    writeRecord: async (value: unknown) => fs.writeFile(filename, JSON.stringify(value), 'utf8'),
    complete: (setup: TotpEnrollmentSetup, token = TOKEN) => coordinator.complete({ ...binding, attemptId: setup.attemptId, token }),
  };
}

function expectNoPlaintext(raw: string, setup: TotpEnrollmentSetup, binding: TotpEnrollmentBinding) {
  expect(raw).not.toContain(setup.secret);
  expect(raw).not.toContain(setup.qrCodeUrl);
  expect(raw).not.toContain(binding.sessionId);
  expect(raw).not.toContain(`"${TOKEN}"`);
  expect(raw).not.toContain('"token"');
  for (const code of setup.backupCodes) expect(raw).not.toContain(code);
}

async function selfFixture() {
  const f = await fixture();
  f.state.user!.needsOnboarding = false;
  f.state.user!.firstLogin = false;
  f.state.session!.user!.needsOnboarding = false;
  const binding: TotpEnrollmentRequest = {
    ...f.binding, mode: 'self-enrollment', primaryReauthRef: 'opaque-server-held-primary-proof',
  };
  const authorization: PrimaryReauthAuthorization = {
    userId: binding.userId, sessionId: binding.sessionId, purpose: 'totp.enroll', method: 'password',
    issuedAt: new Date(START).toISOString(), expiresAt: new Date(START + 60_000).toISOString(),
  };
  const verifiedPasswordHash = f.state.user!.passwordHash;
  const resolver = vi.fn(async (input: Parameters<NonNullable<FileTotpEnrollmentConfig['validatePrimaryReauthentication']>>[0]) => {
    if (input.reference !== binding.primaryReauthRef || input.currentUser.passwordHash !== verifiedPasswordHash) return null;
    return copy(authorization);
  });
  const fresh = (overrides: Partial<FileTotpEnrollmentConfig> = {}) => f.fresh({ validatePrimaryReauthentication: resolver, ...overrides });
  const coordinator = fresh();
  return {
    ...f, binding, authorization, resolver, coordinator, fresh,
    begin: () => coordinator.begin(binding),
    complete: (setup: TotpEnrollmentSetup) => coordinator.complete({ ...binding, attemptId: setup.attemptId, token: TOKEN }),
  };
}

afterEach(async () => {
  vi.restoreAllMocks();
  // Only exact directories returned by this test's mkdtemp are removed.
  for (const directory of ownedDirectories.splice(0)) {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

describe('FileTotpEnrollmentCoordinator self-enrollment v2', () => {
  it('requires a configured server-proof resolver and never treats the opaque reference as authorization', async () => {
    const f = await selfFixture();
    await expect(f.fresh({ validatePrimaryReauthentication: undefined }).begin(f.binding)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    await expect(f.coordinator.begin({ ...f.binding, primaryReauthRef: 'browser-invented-proof' })).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    f.resolver.mockRejectedValueOnce(new Error('private resolver details'));
    await expect(f.begin()).rejects.toMatchObject({ code: 'UNAUTHORIZED', message: 'Current primary reauthentication is required' });
    expect(f.totp.generateSecret).not.toHaveBeenCalled();
    expect(f.project).not.toHaveBeenCalled();
  });

  it.each([
    ['owner', { userId: 'another-user' }],
    ['session', { sessionId: 'another-session' }],
    ['purpose', { purpose: 'account.link' }],
    ['method', { method: 'browser-cookie' }],
    ['future issuance', { issuedAt: new Date(START + 1).toISOString() }],
    ['expired', { expiresAt: new Date(START).toISOString() }],
    ['overlong TTL', { expiresAt: new Date(START + 300_001).toISOString() }],
    ['malformed timestamp', { issuedAt: 'not-time' }],
  ])('denies invalid primary proof %s before creating pending material', async (_label, patch) => {
    const f = await selfFixture();
    Object.assign(f.authorization, patch);
    await expect(f.begin()).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(f.totp.generateSecret).not.toHaveBeenCalled();
    expect(f.project).not.toHaveBeenCalled();
  });

  it('binds pending material to the same proof without writing its reference, session bearer or password hash', async () => {
    const f = await selfFixture();
    const setup = await f.begin();
    const raw = await fs.readFile(f.filename, 'utf8');
    expectNoPlaintext(raw, setup, f.binding);
    expect(raw).not.toContain(f.binding.primaryReauthRef!);
    expect(raw).not.toContain(f.state.user!.passwordHash);
    expect(await f.readRecord()).toMatchObject({ version: 2, mode: 'self-enrollment', state: 'pending' });
    expect(await f.fresh().begin(f.binding)).toEqual(setup);
    f.resolver.mockImplementation(async () => copy(f.authorization));
    await expect(f.coordinator.begin({ ...f.binding, mode: 'self-enrollment', primaryReauthRef: 'different-validated-proof' }))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('completes with only the two factor fields and leaves profile, onboarding, grants and sessions unchanged', async () => {
    const f = await selfFixture();
    const original = copy(f.state.user!);
    const session = copy(f.state.session);
    const setup = await f.begin();
    const receipt = await f.complete(setup);
    expect(receipt).toMatchObject({ version: 2, mode: 'self-enrollment', attemptId: setup.attemptId });
    expect(f.project.mock.calls[0][0].userPatch).toEqual({ totpEnabled: true, totpSecretId: original.handle });
    expect(f.state.user).toEqual({ ...original, totpEnabled: true, totpSecretId: original.handle });
    expect(f.state.session).toEqual(session);
    const applied = await f.readRecord();
    expect(Object.keys(applied).sort()).toEqual(['mode', 'primaryReauthUses', 'receipt', 'sessionDigest', 'state', 'version']);
    expect(JSON.stringify(receipt)).not.toContain(setup.secret);
    for (const code of setup.backupCodes) expect(JSON.stringify(receipt)).not.toContain(code);
  });

  it('accepts current server-verified GitHub reauthentication and rejects provider identity changes', async () => {
    const f = await selfFixture();
    f.authorization.method = 'github';
    f.state.user!.githubId = 42;
    f.resolver.mockImplementation(async ({ reference, currentUser }) =>
      reference === f.binding.primaryReauthRef && currentUser.githubId === 42 ? copy(f.authorization) : null);
    const setup = await f.begin();
    f.state.user!.githubId = 43;
    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(f.totp.verifyTokenWithStep).not.toHaveBeenCalled();
    f.state.user!.githubId = 42;
    await expect(f.complete(setup)).resolves.toMatchObject({ version: 2, mode: 'self-enrollment' });
  });

  it('checks primary credential freshness again after asynchronous resolver, QR and factor verification work', async () => {
    const resolverRace = await selfFixture();
    resolverRace.resolver.mockImplementationOnce(async () => {
      resolverRace.state.user!.passwordHash = 'changed-after-validation-start';
      return copy(resolverRace.authorization);
    });
    await expect(resolverRace.begin()).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    const qrRace = await selfFixture();
    qrRace.totp.generateQRCode.mockImplementationOnce(async () => {
      qrRace.state.session = null;
      return 'data:fixture-qr';
    });
    await expect(qrRace.begin()).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    const factorRace = await selfFixture();
    const setup = await factorRace.begin();
    factorRace.totp.verifyTokenWithStep.mockImplementationOnce(async () => {
      factorRace.state.user!.passwordHash = 'reset-between-factors';
      return { valid: true, step: VERIFIED_STEP };
    });
    await expect(factorRace.complete(setup)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(factorRace.project).not.toHaveBeenCalled();
    expect((await factorRace.readRecord()).state).toBe('pending');
  });

  it('denies a changed current credential before factor verification and expires at the proof deadline', async () => {
    const f = await selfFixture();
    const setup = await f.begin();
    f.state.user!.passwordHash = 'changed-current-credential';
    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(f.totp.verifyTokenWithStep).not.toHaveBeenCalled();
    const expired = await selfFixture();
    const expiredSetup = await expired.begin();
    expired.setTime(Date.parse(expired.authorization.expiresAt));
    await expect(expired.complete(expiredSetup)).rejects.toMatchObject({ code: 'EXPIRED' });
    expect(expired.project).not.toHaveBeenCalled();
  });

  it('does not disclose setup after primary proof expiry during pending publication', async () => {
    const f = await selfFixture();
    const nativeRename = fs.rename.bind(fs);
    vi.spyOn(fs, 'rename').mockImplementationOnce(async (from, to) => {
      await nativeRename(from, to);
      f.setTime(Date.parse(f.authorization.expiresAt));
    });
    await expect(f.begin()).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect((await f.readRecord()).state).toBe('pending');
    expect(f.project).not.toHaveBeenCalled();
  });

  it('finishes a committed projection but refuses UI success if the session expires while applying it', async () => {
    const f = await selfFixture();
    const setup = await f.begin();
    f.project.mockImplementationOnce(async (completion) => {
      await f.applyProjection(completion);
      f.state.session!.expires = new Date(START).toISOString();
    });
    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect((await f.readRecord()).state).toBe('applied');
    expect(f.state.user!.totpEnabled).toBe(true);
  });

  it.each(['onboarding user', 'restricted session', 'existing factor', 'existing backup codes', 'removed user', 'revoked session'])('denies %s', async (caseName) => {
    const f = await selfFixture();
    if (caseName === 'onboarding user') f.state.user!.needsOnboarding = true;
    if (caseName === 'restricted session') f.state.session!.user!.needsOnboarding = true;
    if (caseName === 'existing factor') f.state.totpSecret = {} as NonNullable<TotpEnrollmentCurrentState['totpSecret']>;
    if (caseName === 'existing backup codes') f.state.backupCodes = { userId: f.binding.userId, codes: [], generatedAt: new Date(START).toISOString() };
    if (caseName === 'removed user') Object.assign(f.state.user!, { removedAt: null });
    if (caseName === 'revoked session') f.state.session = null;
    await expect(f.begin()).rejects.toBeDefined();
    expect(f.totp.generateSecret).not.toHaveBeenCalled();
    expect(f.project).not.toHaveBeenCalled();
  });

  it('does not transfer an attempt between onboarding and self-enrollment modes', async () => {
    const f = await selfFixture();
    const setup = await f.begin();
    f.state.user!.needsOnboarding = true;
    f.state.session!.user!.needsOnboarding = true;
    const onboarding = { userId: f.binding.userId, sessionId: f.binding.sessionId };
    await expect(f.coordinator.complete({ ...onboarding, attemptId: setup.attemptId, token: TOKEN })).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(f.coordinator.begin(onboarding)).rejects.toMatchObject({ code: 'CONFLICT' });
    const legacy = await fixture();
    const legacySetup = await legacy.coordinator.begin(legacy.binding);
    legacy.state.user!.needsOnboarding = false;
    legacy.state.session!.user!.needsOnboarding = false;
    await expect(legacy.coordinator.complete({ ...legacy.binding, mode: 'self-enrollment', primaryReauthRef: 'opaque', attemptId: legacySetup.attemptId, token: TOKEN }))
      .rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('replays a committed v2 operation after proof expiry and session revocation, but does not return unauthenticated UI success', async () => {
    const f = await selfFixture();
    const setup = await f.begin();
    f.project.mockImplementationOnce(async (completion) => {
      f.state.totpSecret = copy(completion.totpSecret);
      throw new Error('fixture interrupted projection');
    });
    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    const committed = await f.readRecord<{ completion: TotpEnrollmentCompletion }>();
    f.state.session = null;
    f.setTime(Date.parse(f.authorization.expiresAt) + 1);
    const noProof = f.fresh({ validatePrimaryReauthentication: undefined });
    await expect(noProof.complete({ ...f.binding, attemptId: setup.attemptId, token: TOKEN })).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect((await f.readRecord()).state).toBe('applied');
    expect(f.project.mock.calls[1][0]).toEqual(committed.completion);
    expect(f.state.user!.needsOnboarding).toBe(false);
    expect(f.state.backupCodes).toEqual(committed.completion.backupCodes);
    expect(f.totp.verifyTokenWithStep).toHaveBeenCalledTimes(1);
  });

  it('returns only an idempotent receipt to the same current owner/session after proof expiry without replaying spent material', async () => {
    const f = await selfFixture();
    const setup = await f.begin();
    const receipt = await f.complete(setup);
    f.state.backupCodes!.codes[0].used = true;
    f.setTime(Date.parse(f.authorization.expiresAt) + 1);
    await expect(f.fresh({ validatePrimaryReauthentication: undefined }).complete({ ...f.binding, attemptId: setup.attemptId, token: TOKEN })).resolves.toEqual(receipt);
    expect(f.state.backupCodes!.codes[0].used).toBe(true);
    expect(f.project).toHaveBeenCalledTimes(1);
    f.state.session!.id = 'different-session';
    await expect(f.fresh().complete({ ...f.binding, sessionId: 'different-session', attemptId: setup.attemptId, token: TOKEN })).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('keeps recovery closed if the projection detects a conflicting factor', async () => {
    const f = await selfFixture();
    const setup = await f.begin();
    f.project.mockRejectedValue(new Error('existing factor conflicts with committed material'));
    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    const protectedRead = vi.fn(async () => 'must not run');
    await expect(f.fresh().withReadyAuth(protectedRead)).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    expect(protectedRead).not.toHaveBeenCalled();
    expect((await f.readRecord()).state).toBe('committed');
  });

  it('binds a primary ref once even when pending enrollment expires before the primary proof', async () => {
    const f = await selfFixture();
    const coordinator = f.fresh({ ttlMs: 10_000 });
    const setup = await coordinator.begin(f.binding);
    f.setTime(START + 10_001);
    await expect(coordinator.begin(f.binding)).rejects.toMatchObject({ code: 'CONFLICT' });
    expect((await f.readRecord()).attemptId).toBe(setup.attemptId);
    // A different independently validated proof can replace expired pending
    // material, but its publication must retain the still-live earlier use.
    f.resolver.mockImplementation(async () => copy(f.authorization));
    const replacementBinding = { ...f.binding, mode: 'self-enrollment' as const, primaryReauthRef: 'second-server-proof' };
    const replacement = await coordinator.begin(replacementBinding);
    expect(replacement.attemptId).not.toBe(setup.attemptId);
    expect((await f.readRecord<{ primaryReauthUses: unknown[] }>()).primaryReauthUses).toHaveLength(2);
    f.setTime(START + 20_002);
    await expect(coordinator.begin(f.binding)).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('does not reuse a committed primary proof after out-of-band factor removal', async () => {
    const f = await selfFixture();
    const setup = await f.begin();
    await f.complete(setup);
    f.state.totpSecret = null;
    f.state.backupCodes = null;
    f.state.user!.totpEnabled = false;
    delete f.state.user!.totpSecretId;
    await expect(f.fresh().begin(f.binding)).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(f.project).toHaveBeenCalledTimes(1);
  });

  it('preserves v1 pending bytes and the original v1 material digest without adding mode fields', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    const pendingBytes = await fs.readFile(f.filename, 'utf8');
    await f.fresh().recover();
    expect(await fs.readFile(f.filename, 'utf8')).toBe(pendingBytes);
    const receipt = await f.complete(setup);
    const material = f.project.mock.calls[0][0];
    function legacyCanonical(value: unknown): string {
      if (Array.isArray(value)) return `[${value.map(legacyCanonical).join(',')}]`;
      if (value !== null && typeof value === 'object') {
        const record = value as Record<string, unknown>;
        return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${legacyCanonical(record[key])}`).join(',')}}`;
      }
      return JSON.stringify(value);
    }
    const expected = createHash('sha256').update('tinyland-auth:totp-enrollment:v1\0').update(legacyCanonical(material)).digest('hex');
    expect(receipt.materialDigest).toBe(expected);
    expect(receipt.version).toBe(1);
    expect(material).not.toHaveProperty('mode');
    expect(Object.keys(await f.readRecord()).sort()).toEqual(['receipt', 'sessionDigest', 'state', 'version']);
  });

  it.each(['v2 onboarding mode', 'missing mode', 'extra onboarding patch'])('rejects mode/schema confusion: %s', async (damage) => {
    const f = await selfFixture();
    const setup = await f.begin();
    f.project.mockRejectedValueOnce(new Error('fixture interrupted'));
    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    const record = await f.readRecord<Record<string, any>>();
    if (damage === 'v2 onboarding mode') record.mode = 'onboarding';
    if (damage === 'missing mode') delete record.mode;
    if (damage === 'extra onboarding patch') record.completion.userPatch.needsOnboarding = true;
    await f.writeRecord(record);
    await expect(f.fresh().recover()).rejects.toMatchObject({ code: 'INVALID' });
    expect(f.project).toHaveBeenCalledTimes(1);
  });
});

describe('FileTotpEnrollmentCoordinator pending custody', () => {
  it('resumes identical server-held material after coordinator restart without extending expiry', async () => {
    const f = await fixture();
    const first = await f.coordinator.begin(f.binding);
    f.setTime(START + 30_000);

    const resumed = await f.fresh().begin(f.binding);

    expect(resumed).toEqual(first);
    expect(f.totp.generateSecret).toHaveBeenCalledTimes(1);
    expect(first.attemptId).toMatch(/^[a-f0-9]{48}$/);
    expect(first.backupCodes).toHaveLength(10);
    expect(f.project).not.toHaveBeenCalled();
    expectNoPlaintext(await fs.readFile(f.filename, 'utf8'), first, f.binding);
    expect((await fs.stat(f.filename)).mode & 0o777).toBe(0o600);
    expect((await fs.stat(f.directory)).mode & 0o777).toBe(0o700);
  });

  it('does not disclose or complete another user\'s pending attempt', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    const other = { userId: 'another-user', sessionId: f.binding.sessionId };

    await expect(f.coordinator.begin(other)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    await expect(f.coordinator.complete({ ...other, attemptId: setup.attemptId, token: TOKEN })).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(f.project).not.toHaveBeenCalled();
  });

  it('does not transfer pending custody to another otherwise-valid session', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    f.state.session!.id = 'session:replacement';
    const other = { ...f.binding, sessionId: f.state.session!.id };

    await expect(f.coordinator.begin(other)).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(f.coordinator.complete({ ...other, attemptId: setup.attemptId, token: TOKEN })).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(f.project).not.toHaveBeenCalled();
  });

  it('rejects a changed attempt ID and leaves the original pending attempt intact', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);

    await expect(f.coordinator.complete({ ...f.binding, attemptId: 'a'.repeat(48), token: TOKEN })).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(await f.coordinator.begin(f.binding)).toEqual(setup);
    expect(f.project).not.toHaveBeenCalled();
  });

  it('expires exactly at the deadline and replaces expired setup without accepting its old token', async () => {
    const f = await fixture();
    const first = await f.coordinator.begin(f.binding);
    f.setTime(Date.parse(first.expiresAt));

    await expect(f.complete(first)).rejects.toMatchObject({ code: 'EXPIRED' });
    const replacement = await f.coordinator.begin(f.binding);

    expect(replacement.attemptId).not.toBe(first.attemptId);
    expect(replacement.secret).not.toBe(first.secret);
    await expect(f.complete(first)).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(f.project).not.toHaveBeenCalled();
  });

  it('does not commit a valid verification that crosses the enrollment deadline', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    const entered = deferred();
    const release = deferred();
    f.totp.verifyTokenWithStep.mockImplementationOnce(async () => {
      entered.resolve();
      await release.promise;
      return { valid: true, step: VERIFIED_STEP };
    });
    const completion = f.complete(setup);
    const rejected = expect(completion).rejects.toMatchObject({ code: 'EXPIRED' });
    await entered.promise;
    f.setTime(Date.parse(setup.expiresAt));
    release.resolve();

    await rejected;
    expect((await f.readRecord()).state).toBe('pending');
    expect(f.project).not.toHaveBeenCalled();
  });

  it('does not return expired material when resumed QR generation crosses the deadline', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    f.totp.generateQRCode.mockImplementationOnce(async () => {
      f.setTime(Date.parse(setup.expiresAt));
      return 'data:test-qr,expired';
    });

    await expect(f.fresh().begin(f.binding)).rejects.toMatchObject({ code: 'EXPIRED' });
    expect((await f.readRecord()).attemptId).toBe(setup.attemptId);
    expect(f.totp.generateSecret).toHaveBeenCalledTimes(1);
    expect(f.project).not.toHaveBeenCalled();
  });

  it('rechecks session authority after resumed QR generation', async () => {
    const f = await fixture();
    await f.coordinator.begin(f.binding);
    f.totp.generateQRCode.mockImplementationOnce(async () => {
      f.state.session!.expires = new Date(START).toISOString();
      return 'data:test-qr,session-expired';
    });

    await expect(f.fresh().begin(f.binding)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(f.project).not.toHaveBeenCalled();
  });

  it('rejects time moving before the attempt creation time', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    f.setTime(START - 1);

    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'EXPIRED' });
    expect(f.project).not.toHaveBeenCalled();
  });

  it.each(['12345', '1234567', 'abcdef', '', '000000'])('does not consume pending custody for invalid token %j', async (token) => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);

    await expect(f.complete(setup, token)).rejects.toMatchObject({ code: 'INVALID' });
    expect((await f.readRecord()).state).toBe('pending');
    expect(await f.coordinator.begin(f.binding)).toEqual(setup);
    expect(f.project).not.toHaveBeenCalled();
  });

  it.each([undefined, -1, 1.5, Number.NaN])('requires a valid consumed TOTP step, not just valid=true (%s)', async (step) => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    f.totp.verifyTokenWithStep.mockResolvedValueOnce({ valid: true, step });

    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'INVALID' });
    expect(f.project).not.toHaveBeenCalled();
  });

  it.each([
    ['existing factor', (state: TotpEnrollmentCurrentState) => { state.totpSecret = { userId: state.user!.id } as NonNullable<typeof state.totpSecret>; }],
    ['existing backup codes', (state: TotpEnrollmentCurrentState) => { state.backupCodes = { userId: state.user!.id, codes: [], generatedAt: new Date(START).toISOString() }; }],
    ['enabled factor flag', (state: TotpEnrollmentCurrentState) => { state.user!.totpEnabled = true; }],
    ['factor reference', (state: TotpEnrollmentCurrentState) => { state.user!.totpSecretId = 'existing-factor'; }],
    ['completed onboarding', (state: TotpEnrollmentCurrentState) => { state.user!.needsOnboarding = false; }],
    ['profile not completed', (state: TotpEnrollmentCurrentState) => { state.user!.onboardingStep = 0; }],
  ] as const)('refuses begin and completion when authority gains %s', async (_label, mutate) => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    mutate(f.state);

    await expect(f.coordinator.begin(f.binding)).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(f.project).not.toHaveBeenCalled();
  });

  it.each([
    ['inactive principal', (state: TotpEnrollmentCurrentState) => { state.user!.isActive = false; }],
    ['locked principal', (state: TotpEnrollmentCurrentState) => { state.user!.isLocked = true; }],
    ['missing principal', (state: TotpEnrollmentCurrentState) => { state.user = null; }],
    ['revoked session', (state: TotpEnrollmentCurrentState) => { state.session = null; }],
    ['expired session', (state: TotpEnrollmentCurrentState) => { state.session!.expires = new Date(START).toISOString(); }],
    ['wrong session principal', (state: TotpEnrollmentCurrentState) => { state.session!.userId = 'other-user'; }],
    ['wrong projected principal', (state: TotpEnrollmentCurrentState) => { state.session!.user!.id = 'other-user'; }],
  ] as const)('rechecks the current %s before completion', async (_label, mutate) => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    mutate(f.state);

    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(f.project).not.toHaveBeenCalled();
  });

  it('rechecks current authority after asynchronous TOTP verification', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    f.totp.verifyTokenWithStep.mockImplementationOnce(async () => {
      f.state.user!.isActive = false;
      return { valid: true, step: VERIFIED_STEP };
    });

    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(f.project).not.toHaveBeenCalled();
  });
});

describe('FileTotpEnrollmentCoordinator commit and recovery', () => {
  it('commits encrypted factor, initial hashes and only the narrow security patch before returning a receipt', async () => {
    const f = await fixture();
    const originalUser = copy(f.state.user!);
    const originalSession = copy(f.state.session!);
    const setup = await f.coordinator.begin(f.binding);
    f.project.mockImplementationOnce(async (completion) => {
      const record = await f.readRecord<{ state: string; completion: TotpEnrollmentCompletion }>();
      expect(record.state).toBe('committed');
      expect(record.completion).toEqual(completion);
      expectNoPlaintext(await fs.readFile(f.filename, 'utf8'), setup, f.binding);
      await f.applyProjection(completion);
    });

    const receipt = await f.complete(setup);

    expect(f.project).toHaveBeenCalledTimes(1);
    const completion = f.project.mock.calls[0][0];
    expect(completion.userPatch).toEqual({
      totpEnabled: true, totpSecretId: 'alice', needsOnboarding: true, onboardingStep: 2,
    });
    expect(f.state.user).toEqual({ ...originalUser, ...completion.userPatch });
    expect(f.state.session).toEqual(originalSession);
    expect(f.state.totpSecret).toMatchObject({
      userId: f.binding.userId, handle: 'alice', lastUsedTotpStep: VERIFIED_STEP,
      lastUsedAt: receipt.completedAt, backupCodesGenerated: true,
    });
    expect(f.state.backupCodes!.codes.map((code) => code.hash)).toEqual(setup.backupCodes.map(hashBackupCode));
    expect(f.state.backupCodes!.codes.every((code) => code.used === false)).toBe(true);
    expect(receipt).toEqual({
      version: 1, attemptId: setup.attemptId, userId: f.binding.userId, handle: 'alice',
      completedAt: new Date(START).toISOString(), materialDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
    const applied = await f.readRecord();
    expect(applied.state).toBe('applied');
    expect(Object.keys(applied).sort()).toEqual(['receipt', 'sessionDigest', 'state', 'version']);
    expectNoPlaintext(JSON.stringify(applied), setup, f.binding);
  });

  it.each([2, 3])('does not rewind an existing onboarding step %s or complete onboarding', async (step) => {
    const f = await fixture();
    f.state.user!.onboardingStep = step;
    const setup = await f.coordinator.begin(f.binding);

    await f.complete(setup);

    expect(f.state.user!.onboardingStep).toBe(step);
    expect(f.state.user!.needsOnboarding).toBe(true);
    expect(f.state.user!.role).toBe('member');
  });

  it.each(['factor', 'backup codes', 'principal patch'])('replays the frozen commit after interruption following %s projection', async (stage) => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    f.project.mockImplementationOnce(async (completion) => {
      f.state.totpSecret = copy(completion.totpSecret);
      if (stage !== 'factor') f.state.backupCodes = copy(completion.backupCodes);
      if (stage === 'principal patch') Object.assign(f.state.user!, completion.userPatch);
      throw new Error(`power loss after ${stage} projection`);
    });

    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    const committed = await f.readRecord<{ state: string; completion: TotpEnrollmentCompletion }>();
    expect(committed.state).toBe('committed');
    if (stage === 'factor') expect(f.state.backupCodes).toBeNull();
    expect(f.state.user!.totpEnabled).toBe(stage === 'principal patch');
    f.state.session = null;
    f.setTime(Date.parse(setup.expiresAt) + 1);
    const protectedRead = vi.fn(async () => copy(f.state));

    const observed = await f.fresh().withReadyAuth(protectedRead);

    expect(observed.totpSecret).toEqual(committed.completion.totpSecret);
    expect(observed.backupCodes).toEqual(committed.completion.backupCodes);
    expect(observed.user).toMatchObject(committed.completion.userPatch);
    expect(f.project).toHaveBeenCalledTimes(2);
    expect(f.project.mock.calls[1][0]).toEqual(committed.completion);
    expect((await f.readRecord()).state).toBe('applied');
    expect(f.totp.verifyTokenWithStep).toHaveBeenCalledTimes(1);
  });

  it('keeps guarded reads and writes closed across repeated projection failures until recovery succeeds', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    f.project.mockRejectedValue(new Error('backing storage unavailable'));
    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    const protectedOperation = vi.fn(async () => 'must not run');

    await expect(f.coordinator.withReadyAuth(protectedOperation)).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    await expect(f.fresh().withReadyAuth(protectedOperation)).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    await expect(f.fresh().recover()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    expect(protectedOperation).not.toHaveBeenCalled();

    f.project.mockImplementation(f.applyProjection);
    await f.fresh().recover();
    await expect(f.coordinator.withReadyAuth(protectedOperation)).resolves.toBe('must not run');
    expect(protectedOperation).toHaveBeenCalledTimes(1);
  });

  it('does not reopen a nested gate when a caller catches an incomplete projection', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    const protectedOperation = vi.fn(async () => 'protected');
    f.project.mockRejectedValue(new Error('partial projection'));

    await f.coordinator.withReadyAuth(async () => {
      await expect(f.complete(setup)).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
      await expect(f.coordinator.withReadyAuth(protectedOperation)).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    });

    expect(protectedOperation).not.toHaveBeenCalled();
    f.project.mockImplementation(f.applyProjection);
    await f.coordinator.recover();
  });

  it('does not treat a renamed applied record as durable after directory sync fails', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    const nativeOpen = fs.open.bind(fs);
    let failAppliedSync = true;
    vi.spyOn(fs, 'open').mockImplementation(async (filename, flags, mode) => {
      const handle = await nativeOpen(filename, flags, mode);
      if (filename === f.directory && flags === 'r') {
        const nativeSync = handle.sync.bind(handle);
        vi.spyOn(handle, 'sync').mockImplementation(async () => {
          if (failAppliedSync && (await f.readRecord()).state === 'applied') {
            throw new Error('directory fsync unavailable');
          }
          await nativeSync();
        });
      }
      return handle;
    });
    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    expect((await f.readRecord()).state).toBe('applied');
    const protectedOperation = vi.fn(async () => 'protected');

    await expect(f.fresh().withReadyAuth(protectedOperation)).rejects.toBeDefined();
    expect(protectedOperation).not.toHaveBeenCalled();
    failAppliedSync = false;
    await expect(f.fresh().withReadyAuth(protectedOperation)).resolves.toBe('protected');
    expect(f.project).toHaveBeenCalledTimes(1);
  });

  it('does not replay a renamed commit before durable publication can be acknowledged', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    const nativeOpen = fs.open.bind(fs);
    let failCommittedSync = true;
    vi.spyOn(fs, 'open').mockImplementation(async (filename, flags, mode) => {
      const handle = await nativeOpen(filename, flags, mode);
      if (filename === f.directory && flags === 'r') {
        const nativeSync = handle.sync.bind(handle);
        vi.spyOn(handle, 'sync').mockImplementation(async () => {
          if (failCommittedSync && (await f.readRecord()).state === 'committed') {
            throw new Error('commit directory fsync unavailable');
          }
          await nativeSync();
        });
      }
      return handle;
    });

    await expect(f.complete(setup)).rejects.toBeDefined();
    expect((await f.readRecord()).state).toBe('committed');
    expect(f.project).not.toHaveBeenCalled();
    const protectedOperation = vi.fn(async () => 'protected');
    await expect(f.fresh().withReadyAuth(protectedOperation)).rejects.toBeDefined();
    expect(protectedOperation).not.toHaveBeenCalled();
    expect(f.project).not.toHaveBeenCalled();

    failCommittedSync = false;
    await expect(f.fresh().withReadyAuth(protectedOperation)).resolves.toBe('protected');
    expect(f.project).toHaveBeenCalledTimes(1);
  });

  it('does not project a committed factor that the current encryption key cannot authenticate', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    f.project.mockRejectedValueOnce(new Error('interrupted projection'));
    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    const protectedOperation = vi.fn(async () => 'protected');
    const wrongKey = f.fresh({
      totp: { ...f.totp, decrypt: () => { throw new Error('key unavailable or changed'); } },
    });

    await expect(wrongKey.withReadyAuth(protectedOperation)).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    expect(protectedOperation).not.toHaveBeenCalled();
    expect(f.project).toHaveBeenCalledTimes(1);
    expect((await f.readRecord()).state).toBe('committed');
    await f.fresh().recover();
    expect(f.project).toHaveBeenCalledTimes(2);
  });

  it('never reprojects applied retries over used backup codes, a later factor, or finished onboarding', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    const receipt = await f.complete(setup);
    f.state.backupCodes!.codes[0].used = true;
    f.state.backupCodes!.codes[0].usedAt = new Date(START + 1_000).toISOString();
    f.state.totpSecret!.encryptedSecret = 'later-rotated-factor';
    f.state.totpSecret!.lastUsedTotpStep = VERIFIED_STEP + 1;
    f.state.user!.needsOnboarding = false;
    f.state.user!.onboardingStep = 3;
    const laterState = copy(f.state);
    f.setTime(Date.parse(setup.expiresAt) + 1);
    const fresh = f.fresh();

    await fresh.recover();
    await expect(fresh.complete({ ...f.binding, attemptId: setup.attemptId, token: TOKEN })).resolves.toEqual(receipt);
    await expect(f.complete(setup)).resolves.toEqual(receipt);

    expect(f.state).toEqual(laterState);
    expect(f.project).toHaveBeenCalledTimes(1);
    expect(f.totp.verifyTokenWithStep).toHaveBeenCalledTimes(1);
  });

  it('does not return an applied receipt to a different session or deactivated user', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    await f.complete(setup);
    f.state.session!.id = 'session:other';

    await expect(f.coordinator.complete({ ...f.binding, sessionId: f.state.session!.id, attemptId: setup.attemptId, token: TOKEN })).rejects.toMatchObject({ code: 'CONFLICT' });
    f.state.session!.id = f.binding.sessionId;
    f.state.user!.isActive = false;
    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(f.project).toHaveBeenCalledTimes(1);
  });
});

describe('FileTotpEnrollmentCoordinator serialization and fail-closed storage', () => {
  it('serializes simultaneous begins and completes across coordinators sharing a directory', async () => {
    const f = await fixture();
    const peer = f.fresh();
    const setups = await Promise.all([
      f.coordinator.begin(f.binding), peer.begin(f.binding), f.coordinator.begin(f.binding),
    ]);
    expect(setups[1]).toEqual(setups[0]);
    expect(setups[2]).toEqual(setups[0]);
    expect(f.totp.generateSecret).toHaveBeenCalledTimes(1);

    const input = { ...f.binding, attemptId: setups[0].attemptId, token: TOKEN };
    const receipts = await Promise.all([
      f.coordinator.complete(input), peer.complete(input), f.coordinator.complete(input),
    ]);

    expect(receipts[1]).toEqual(receipts[0]);
    expect(receipts[2]).toEqual(receipts[0]);
    expect(f.project).toHaveBeenCalledTimes(1);
    expect(f.totp.verifyTokenWithStep).toHaveBeenCalledTimes(1);
  });

  it('permits awaited nested gates and enrollment without deadlocking', async () => {
    const f = await fixture();

    const receipt = await f.coordinator.withReadyAuth(async () => {
      const setup = await f.fresh().withReadyAuth(() => f.coordinator.begin(f.binding));
      return f.coordinator.withReadyAuth(() => f.complete(setup));
    });

    expect(receipt.userId).toBe(f.binding.userId);
    expect(f.project).toHaveBeenCalledTimes(1);
  });

  it('holds the root gate for children appended while its original child tail is draining', async () => {
    const f = await fixture();
    const childAEntered = deferred();
    const releaseA = deferred();
    const enqueueLateChild = deferred();
    const childBEntered = deferred();
    const releaseB = deferred();
    const events: string[] = [];
    let childA!: Promise<void>;
    let childB!: Promise<void>;
    let enqueueB!: Promise<void>;
    let outerSettled = false;
    const outer = f.coordinator.withReadyAuth(async () => {
      childA = f.coordinator.withReadyAuth(async () => {
        childAEntered.resolve();
        await releaseA.promise;
        events.push('child A finished');
      });
      // This callback inherits the OUTER context, but only runs after that
      // operation has returned and started draining child A's original tail.
      enqueueB = enqueueLateChild.promise.then(() => {
        childB = f.coordinator.withReadyAuth(async () => {
          events.push('child B entered');
          childBEntered.resolve();
          await releaseB.promise;
          events.push('child B finished');
        });
      });
      return 'outer operation returned';
    }).then((result) => {
      outerSettled = true;
      return result;
    });
    await childAEntered.promise;
    const nextRootOperation = vi.fn(async () => { events.push('next root entered'); });
    const nextRoot = f.fresh().withReadyAuth(nextRootOperation);
    enqueueLateChild.resolve();
    await enqueueB;
    releaseA.resolve();
    await childBEntered.promise;

    try {
      // Drain promise continuations so an incorrectly released outer gate
      // cannot hide behind the order in which child B signaled its entry.
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(outerSettled).toBe(false);
      expect(nextRootOperation).not.toHaveBeenCalled();
    } finally {
      releaseB.resolve();
      await Promise.all([outer, childA, childB, nextRoot]);
    }

    expect(events).toEqual([
      'child A finished', 'child B entered', 'child B finished', 'next root entered',
    ]);
  });

  it('does not create competing successful attempts from concurrent nested begins', async () => {
    const f = await fixture();
    const peer = f.fresh();

    const outcomes = await f.coordinator.withReadyAuth(() => Promise.allSettled([
      f.coordinator.begin(f.binding), peer.begin(f.binding),
    ]));
    const fulfilled = outcomes.filter((result) => result.status === 'fulfilled');
    expect(fulfilled.length).toBeGreaterThan(0);
    for (const outcome of outcomes) {
      if (outcome.status === 'fulfilled') expect(outcome.value).toEqual(fulfilled[0].value);
      else expect(outcome.reason).toMatchObject({ name: 'TotpEnrollmentError' });
    }
    expect(f.totp.generateSecret).toHaveBeenCalledTimes(1);
    expect(await f.coordinator.begin(f.binding)).toEqual(fulfilled[0].value);
  });

  it('does not verify or project twice from concurrent nested completions', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    const input = { ...f.binding, attemptId: setup.attemptId, token: TOKEN };

    const outcomes = await f.coordinator.withReadyAuth(() => Promise.allSettled([
      f.coordinator.complete(input), f.fresh().complete(input),
    ]));
    const fulfilled = outcomes.filter((result) => result.status === 'fulfilled');
    expect(fulfilled.length).toBeGreaterThan(0);
    for (const outcome of outcomes) {
      if (outcome.status === 'fulfilled') expect(outcome.value).toEqual(fulfilled[0].value);
      else expect(outcome.reason).toMatchObject({ name: 'TotpEnrollmentError' });
    }
    expect(f.totp.verifyTokenWithStep).toHaveBeenCalledTimes(1);
    expect(f.project).toHaveBeenCalledTimes(1);
  });

  it('prevents a projection from recursively entering protected auth', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    const protectedOperation = vi.fn(async () => 'protected');
    f.project.mockImplementation(async () => {
      await f.coordinator.withReadyAuth(protectedOperation);
    });

    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    expect(protectedOperation).not.toHaveBeenCalled();
    expect((await f.readRecord()).state).toBe('committed');
  });

  it('waits for an in-progress projection before admitting another request', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    const entered = deferred();
    const release = deferred();
    f.project.mockImplementationOnce(async (completion) => {
      entered.resolve();
      await release.promise;
      await f.applyProjection(completion);
    });
    const completion = f.complete(setup);
    await entered.promise;
    const protectedOperation = vi.fn(async () => f.state.user!.totpEnabled);
    const waiting = f.fresh().withReadyAuth(protectedOperation);
    expect(protectedOperation).not.toHaveBeenCalled();
    release.resolve();

    await completion;
    await expect(waiting).resolves.toBe(true);
  });

  it.each(['secret', 'recoveryCodes'] as const)('rejects authenticated ciphertext tampering in pending %s', async (field) => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    const record = await f.readRecord<Record<'secret' | 'recoveryCodes', EncryptedData>>();
    const tag = Buffer.from(record[field].tag, 'base64');
    tag[0] ^= 0xff;
    record[field].tag = tag.toString('base64');
    await f.writeRecord(record);

    await expect(f.fresh().begin(f.binding)).rejects.toBeDefined();
    await expect(f.complete(setup)).rejects.toBeDefined();
    expect(f.project).not.toHaveBeenCalled();
  });

  it('rejects valid ciphertext whose recovery codes no longer match their hashes', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    const record = await f.readRecord<{ recoveryCodes: EncryptedData }>();
    record.recoveryCodes = f.totp.encrypt(JSON.stringify(setup.backupCodes.map(() => 'FFFF-FFFF')));
    await f.writeRecord(record);

    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'INVALID' });
    expect(f.project).not.toHaveBeenCalled();
  });

  it.each(['invalid JSON', 'unexpected fields', 'wrong filename identity', 'invalid backup state', 'unknown version'])('fails closed on %s before a guarded operation', async (damage) => {
    const f = await fixture();
    await f.coordinator.begin(f.binding);
    const record = await f.readRecord<{ userId: string; version: number; backupCodes: { codes: { used: boolean }[] }; unexpected?: boolean }>();
    if (damage === 'invalid JSON') await fs.writeFile(f.filename, '{', 'utf8');
    else {
      if (damage === 'unexpected fields') record.unexpected = true;
      if (damage === 'wrong filename identity') record.userId = 'different-user';
      if (damage === 'invalid backup state') record.backupCodes.codes[0].used = true;
      if (damage === 'unknown version') record.version = 99;
      await f.writeRecord(record);
    }
    const protectedOperation = vi.fn(async () => 'protected');

    await expect(f.fresh().withReadyAuth(protectedOperation)).rejects.toBeDefined();
    expect(protectedOperation).not.toHaveBeenCalled();
    expect(f.project).not.toHaveBeenCalled();
  });

  it('rejects a committed projection whose material no longer matches its receipt', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    f.project.mockRejectedValueOnce(new Error('interrupted projection'));
    await expect(f.complete(setup)).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    const record = await f.readRecord<{ completion: TotpEnrollmentCompletion }>();
    record.completion.totpSecret.encryptedSecret = 'tampered-material';
    await f.writeRecord(record);
    const protectedOperation = vi.fn(async () => 'protected');

    await expect(f.fresh().withReadyAuth(protectedOperation)).rejects.toMatchObject({ code: 'INVALID' });
    expect(protectedOperation).not.toHaveBeenCalled();
    expect(f.project).toHaveBeenCalledTimes(1);
  });

  it('ignores unpublished temporary records rather than projecting them', async () => {
    const f = await fixture();
    await fs.writeFile(path.join(f.directory, 'unpublished.json.interrupted.tmp'), '{broken', 'utf8');
    const protectedOperation = vi.fn(async () => 'ready');

    await expect(f.coordinator.withReadyAuth(protectedOperation)).resolves.toBe('ready');
    expect(f.project).not.toHaveBeenCalled();
  });

  it('does not project or consume pending custody when commit publication fails before rename', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(f.binding);
    vi.spyOn(fs, 'rename').mockRejectedValueOnce(new Error('commit rename unavailable'));

    await expect(f.complete(setup)).rejects.toThrow('commit rename unavailable');
    expect(f.project).not.toHaveBeenCalled();
    expect((await f.readRecord()).state).toBe('pending');
    expect(await fs.readdir(f.directory)).toEqual([path.basename(f.filename)]);
    await expect(f.complete(setup)).resolves.toMatchObject({ attemptId: setup.attemptId });
    expect(f.project).toHaveBeenCalledTimes(1);
  });
});
