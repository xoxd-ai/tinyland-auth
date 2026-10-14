import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { installSeams } from '../src/core/seams/index.js';
import { TOTPService } from '../src/core/totp/index.js';
import { generateAuthenticatorToken } from '../src/totp/otplib-compat.js';
import { hashBackupCode } from '../src/core/backup-codes/index.js';
import { FileBootstrapCoordinator, type BootstrapCompletion, type FileBootstrapConfig } from '../src/storage/file-bootstrap.js';
import { FileTotpEnrollmentCoordinator } from '../src/storage/file-totp-enrollment.js';
import { FileTotpRetirementCoordinator } from '../src/storage/file-totp-retirement.js';
import { FileActionStepUpStore } from '../src/storage/action-step-up.js';
import type { AdminUser, BackupCodeSet, EncryptedData, EncryptedTOTPSecret } from '../src/types/auth.js';

// RS6 (W8 r2): the method functions the coordinators captured at module load,
// read before any spy replaces a prototype property.
const AUTHORITY_METHODS = ['generateSecret', 'generateQRCode', 'encrypt', 'decrypt', 'verifyTokenWithStep'] as const;
const ORIGINAL_METHODS = Object.fromEntries(
  AUTHORITY_METHODS.map((name) => [name, TOTPService.prototype[name]]),
) as Record<(typeof AUTHORITY_METHODS)[number], (...args: never[]) => unknown>;

const START = Date.parse('2026-09-24T02:00:00.000Z');
const HASH = '$2b$04$' + 'A'.repeat(53);
// RS6: no stubbed TOTP. The coordinator runs the package's own secret
// generation and RFC 6238 verification; tests compute real codes for the test
// clock installed through the NODE_ENV=test seam registry.
const STEP = Math.floor(START / 30_000);
const tokenAt = (secret: string, ms: number) => generateAuthenticatorToken(secret, Math.floor(ms / 1000));
/** A 6-digit code that matches none of the accepted window steps at `ms`. */
function wrongTokenAt(secret: string, ms: number): string {
  const window = new Set([-30_000, 0, 30_000].map((offset) => tokenAt(secret, ms + offset)));
  for (let n = 0; ; n++) {
    const candidate = String(n).padStart(6, '0');
    if (!window.has(candidate)) return candidate;
  }
}
const input = { handle: 'first-admin', passwordHash: HASH };
const PROFILE = { displayName: 'First Admin', bio: 'Private profile', pronouns: 'they/them', visibility: 'draft' as const };
const roots: string[] = [];
const copy = <T>(value: T): T => structuredClone(value);

afterEach(async () => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) await fs.rm(root, { recursive: true, force: true });
});

async function fixture(overrides: Partial<FileBootstrapConfig> = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'auth-bootstrap-'));
  roots.push(root);
  const directory = path.join(root, 'bootstrap');
  const filename = path.join(directory, 'bootstrap.json');
  let time = START;
  const totp = new TOTPService({ encryptionKey: 'test-only-bootstrap-key-never-use-in-deployment', issuer: 'Bootstrap Test' });
  // The real service reads the same test clock as the coordinators.
  installSeams(totp, { clock: { now: () => time } });
  // Deny-only gate: observes each NEW completion right before the coordinator
  // verifies the code itself; tests also use it to inject races at that point.
  const completionGate = vi.fn(async (_operation: 'bootstrap.complete'): Promise<void> => undefined);
  const current: { users: AdminUser[]; factor: EncryptedTOTPSecret | null; codes: BackupCodeSet | null; profile: unknown } = { users: [], factor: null, codes: null, profile: null };
  const storage = {
    getAllUsers: vi.fn(async () => copy(current.users)),
    getTOTPSecret: vi.fn(async () => copy(current.factor)),
    getBackupCodes: vi.fn(async () => copy(current.codes)),
  };
  // Real existing reentrant auth gate, shared by fresh coordinator instances.
  const gate = new FileTotpEnrollmentCoordinator({
    directory: path.join(root, 'enrollment'), totp,
    loadCurrent: async () => { throw new Error('Unused'); },
    project: async () => { throw new Error('Unused'); },
  });
  let failAfter: 'factor' | 'codes' | 'profile' | 'user' | undefined;
  const project = vi.fn(async (completion: BootstrapCompletion) => {
    current.factor ??= copy(completion.totpSecret);
    if (failAfter === 'factor') throw new Error('injected factor failure');
    current.codes ??= copy(completion.backupCodes);
    if (failAfter === 'codes') throw new Error('injected codes failure');
    current.profile ??= copy(completion.profile ?? null);
    if (failAfter === 'profile') throw new Error('injected profile failure');
    if (!current.users.length) current.users.push(copy(completion.user));
    if (failAfter === 'user') throw new Error('injected user failure');
  });
  const config: FileBootstrapConfig = {
    directory, scope: 'test-installation', totp, storage, project, beforeComplete: completionGate,
    withExclusiveAuth: (operation) => gate.withReadyAuth(operation),
    ...overrides,
  };
  const clocked = <T extends object>(service: T): T => {
    installSeams(service, { clock: { now: () => time } });
    return service;
  };
  const fresh = (options: Partial<FileBootstrapConfig> = {}) => clocked(new FileBootstrapCoordinator({ ...config, ...options }));
  const read = async () => {
    const envelope = JSON.parse(await fs.readFile(filename, 'utf8')) as { version: number; encrypted: EncryptedData };
    return JSON.parse(totp.decrypt(envelope.encrypted));
  };
  const write = async (value: unknown) => fs.writeFile(filename, JSON.stringify({ version: 1, encrypted: totp.encrypt(JSON.stringify(value)) }));
  return { root, directory, filename, totp, storage, current, project, gate, fresh, coordinator: fresh(), read, write, completionGate,
    /** The valid code for this setup at the current (or given) test time. */
    token: (setup: { secret: string }, at = time) => tokenAt(setup.secret, at),
    wrongToken: (setup: { secret: string }, at = time) => wrongTokenAt(setup.secret, at),
    setTime: (value: number) => { time = value; }, failAfter: (value?: typeof failAfter) => { failAfter = value; } };
}

describe('encrypted durable bootstrap coordinator', () => {
  it('retains strict unknown-field validation across every authenticated journal state', async () => {
    const f = await fixture();
    await f.coordinator.begin(input);
    const original = await f.read();
    const pending = original.record;
    const malformed = [
      { ...pending, attemptId: 42 }, { ...pending, userId: null },
      { ...pending, secret: 42 }, { ...pending, backupCodesAcknowledged: 'true' },
      { ...pending, backupCodes: [...pending.backupCodes.slice(0, 9), 42] },
      { ...pending, backupCodes: Array(10).fill(pending.backupCodes[0]) },
      { ...pending, expiresAt: 42 }, { ...pending, profile: { role: 'super_admin' } },
      { state: 'pending' }, { ...pending, state: 'unknown' },
      { state: 'committed', referenceDigest: pending.referenceDigest, completion: {}, receipt: {} },
      { state: 'applied', referenceDigest: pending.referenceDigest, receipt: {} },
    ];
    for (const record of malformed) {
      await f.write({ ...original, record });
      await expect(f.fresh().recover()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    }
    expect(f.project).not.toHaveBeenCalled();
    expect(f.completionGate).not.toHaveBeenCalled();
    await f.write(original);
    await expect(f.fresh().recover()).resolves.toBeUndefined();
  });

  it('normalizes a new uppercase handle across setup, journal, factor and frozen profile owner', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin({ ...input, handle: '  First-ADMIN  ', profile: PROFILE });
    expect(setup.handle).toBe('first-admin');
    expect(setup.secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(setup.qrCodeUrl).toMatch(/^data:image\/png;base64,/);
    const pending = (await f.read()).record;
    expect(pending.handle).toBe('first-admin');
    expect((await f.fresh().read(setup.reference)).handle).toBe('first-admin');
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    const receipt = await f.coordinator.complete({ reference: setup.reference, token: f.token(setup) });
    const projected = f.project.mock.calls[0][0];
    expect(projected.user).toMatchObject({ id: pending.userId, handle: 'first-admin', totpSecretId: 'first-admin' });
    expect(projected.totpSecret).toMatchObject({ userId: pending.userId, handle: 'first-admin' });
    expect(projected.backupCodes.userId).toBe(pending.userId);
    // The app derives the profile pathname from this exact frozen owner.
    expect(projected.profile).toEqual(PROFILE);
    expect(receipt).toMatchObject({ userId: pending.userId, handle: 'first-admin' });
  });

  it('accepts a numeric initial character for a new bootstrap identity', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin({ ...input, handle: '7Admin' });
    expect(setup.handle).toBe('7admin');
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    const receipt = await f.coordinator.complete({ reference: setup.reference, token: f.token(setup) });
    expect(receipt.handle).toBe('7admin');
    expect(f.current.users[0].handle).toBe('7admin');
    expect(f.current.factor!.handle).toBe('7admin');
  });

  it('rejects an underscore initial character before generating or writing setup material', async () => {
    const f = await fixture();
    await expect(f.coordinator.begin({ ...input, handle: '_admin' })).rejects.toMatchObject({ code: 'INVALID' });
    expect(f.project).not.toHaveBeenCalled();
    expect(await fs.readdir(f.root)).toEqual([]);
  });

  it('is opt-in and does not touch an existing installation with no journal', async () => {
    const f = await fixture();
    f.current.users = [{ id: 'existing', handle: 'operator' } as AdminUser];
    await f.coordinator.recover();
    // The pre-existing enrollment gate creates its own directory, not ours.
    expect(await fs.readdir(f.root)).toEqual(['enrollment']);
    expect(f.project).not.toHaveBeenCalled();
    await expect(f.coordinator.begin(input)).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(f.current.users).toEqual([{ id: 'existing', handle: 'operator' }]);
    expect(await fs.readdir(f.root)).toEqual(['enrollment']);
  });

  it('encrypts every credential/profile field, persists private modes, and resumes after restart', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin({ ...input, profile: PROFILE });
    const raw = await fs.readFile(f.filename, 'utf8');
    for (const secret of [HASH, setup.secret, input.handle, setup.reference, PROFILE.bio, ...setup.backupCodes]) expect(raw).not.toContain(secret);
    expect(Object.keys(JSON.parse(raw)).sort()).toEqual(['encrypted', 'version']);
    expect((await fs.stat(f.directory)).mode & 0o777).toBe(0o700);
    expect((await fs.stat(f.filename)).mode & 0o777).toBe(0o600);
    expect(await f.fresh().read(setup.reference)).toEqual(setup);
    expect(JSON.stringify(await f.read())).not.toContain(setup.reference);
    expect(f.current.users).toEqual([]);
    expect(f.project).not.toHaveBeenCalled();
  });

  it('updates only bounded profile metadata without extending TTL or replacing factor material', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(input);
    f.setTime(START + 1000);
    await f.coordinator.updateProfile(setup.reference, PROFILE);
    const resumed = await f.coordinator.read(setup.reference);
    expect(resumed).toEqual({ ...setup, profile: PROFILE });
    await expect(f.coordinator.updateProfile(setup.reference, { ...PROFILE, role: 'super_admin' } as never)).rejects.toMatchObject({ code: 'INVALID' });
  });

  it('requires a durable acknowledgment of the same attempt before even verifying completion', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(input);
    expect(setup.backupCodesAcknowledged).toBe(false);
    await expect(f.coordinator.complete({ reference: setup.reference, token: f.token(setup) })).rejects.toMatchObject({ code: 'INVALID' });
    expect(f.completionGate).not.toHaveBeenCalled();
    expect(f.project).not.toHaveBeenCalled();
    await expect(f.coordinator.acknowledgeBackupCodes('0'.repeat(64))).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect((await f.read()).record.backupCodesAcknowledged).toBe(false);
    await f.fresh().acknowledgeBackupCodes(setup.reference);
    expect((await f.read()).record.backupCodesAcknowledged).toBe(true);
    await f.fresh().updateProfile(setup.reference, PROFILE);
    await f.fresh().acknowledgeBackupCodes(setup.reference);
    expect(await f.fresh().read(setup.reference)).toEqual({ ...setup, profile: PROFILE, backupCodesAcknowledged: true });
    await expect(f.fresh().complete({ reference: setup.reference, token: f.token(setup) })).resolves.toMatchObject({ handle: input.handle });
  });

  it('does not transfer acknowledgment to a replacement or permit acknowledgment after expiry', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(input);
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    f.setTime(START + 600_000);
    await expect(f.fresh().acknowledgeBackupCodes(setup.reference)).rejects.toMatchObject({ code: 'EXPIRED' });
    const replacement = await f.fresh().begin(input);
    expect(replacement.backupCodesAcknowledged).toBe(false);
    await expect(f.fresh().acknowledgeBackupCodes(setup.reference)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    await expect(f.fresh().complete({ reference: replacement.reference, token: f.token(replacement) })).rejects.toMatchObject({ code: 'INVALID' });
    expect(f.project).not.toHaveBeenCalled();
  });

  it('retains unacknowledged pending when acknowledgment publication fails', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(input);
    vi.spyOn(fs, 'rename').mockRejectedValueOnce(new Error('ack publication failed'));
    await expect(f.coordinator.acknowledgeBackupCodes(setup.reference)).rejects.toThrow('ack publication failed');
    expect((await f.read()).record.backupCodesAcknowledged).toBe(false);
    await expect(f.fresh().complete({ reference: setup.reference, token: f.token(setup) })).rejects.toMatchObject({ code: 'INVALID' });
  });

  it('rejects a retained namespace before generating setup and rechecks after asynchronous generation', async () => {
    const namespace = vi.fn(async (): Promise<void> => { throw new Error('private namespace path must not escape'); });
    const f = await fixture({ assertNamespaceAvailable: namespace });
    await expect(f.coordinator.begin(input)).rejects.toMatchObject({ code: 'CONFLICT', message: 'Bootstrap state requires review or is unavailable' });
    expect(namespace).toHaveBeenCalledTimes(1);
    expect(await fs.readdir(f.root)).toEqual(['enrollment']);
    namespace.mockResolvedValueOnce(undefined);
    await expect(f.fresh().begin(input)).rejects.toMatchObject({ code: 'CONFLICT' });
    // Passed before generation, refused by the recheck after it.
    expect(namespace).toHaveBeenCalledTimes(3);
    expect(await fs.readdir(f.root)).toEqual(['enrollment']);
  });

  it('checks normalized namespace under the same auth gate immediately before commit', async () => {
    const f = await fixture();
    let held = 0;
    let namespaceOccupied = false;
    const namespace = vi.fn(async (handle: string) => {
      expect(held).toBeGreaterThan(0);
      expect(handle).toBe('first-admin');
      if (namespaceOccupied) throw new Error('namespace retained');
    });
    const coordinator = f.fresh({
      assertNamespaceAvailable: namespace,
      withExclusiveAuth: (operation) => f.gate.withReadyAuth(async () => {
        held++;
        try { return await operation(); } finally { held--; }
      }),
    });
    const setup = await coordinator.begin({ ...input, handle: 'First-ADMIN' });
    await coordinator.acknowledgeBackupCodes(setup.reference);
    const checksBeforeComplete = namespace.mock.calls.length;
    f.completionGate.mockImplementationOnce(async () => {
      namespaceOccupied = true;
    });
    await expect(coordinator.complete({ reference: setup.reference, token: f.token(setup) })).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(namespace).toHaveBeenCalledTimes(checksBeforeComplete + 1);
    expect((await f.read()).record.state).toBe('pending');
    expect(f.project).not.toHaveBeenCalled();
  });

  it('does not re-run empty namespace authority during committed or applied recovery', async () => {
    const namespace = vi.fn(async () => undefined);
    const f = await fixture({ assertNamespaceAvailable: namespace });
    const setup = await f.coordinator.begin(input);
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    f.failAfter('profile');
    await expect(f.coordinator.complete({ reference: setup.reference, token: f.token(setup) })).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    const checksAtCommit = namespace.mock.calls.length;
    namespace.mockRejectedValue(new Error('profile now exists by committed authority'));
    f.failAfter();
    f.setTime(START + 600_001);
    await f.fresh().recover();
    await f.fresh().recover();
    expect(namespace).toHaveBeenCalledTimes(checksAtCommit);
    expect(f.current.users).toHaveLength(1);
    expect((await f.read()).record.state).toBe('applied');
  });

  it('rejects wrong, malformed, missing, expired, and future-clock references without disclosure', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(input);
    for (const reference of ['', 'short', 'A'.repeat(64), '0'.repeat(64)]) {
      await expect(f.fresh().read(reference)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    }
    f.setTime(START - 1);
    await expect(f.fresh().read(setup.reference)).rejects.toMatchObject({ code: 'EXPIRED' });
    f.setTime(START + 600_000);
    await expect(f.fresh().read(setup.reference)).rejects.toMatchObject({ code: 'EXPIRED' });
    await expect(f.fresh().complete({ reference: setup.reference, token: f.token(setup) })).rejects.toMatchObject({ code: 'EXPIRED' });
    expect(f.project).not.toHaveBeenCalled();
  });

  it('serializes real shared-gate concurrent reservations and rejects alternative initialization while reserved', async () => {
    const f = await fixture();
    const outcomes = await Promise.allSettled([f.coordinator.begin(input), f.fresh().begin({ ...input, handle: 'other-admin' })]);
    expect(outcomes.map((item) => item.status).sort()).toEqual(['fulfilled', 'rejected']);
    await expect(f.fresh().assertAvailable()).rejects.toMatchObject({ code: 'CONFLICT' });
    await f.gate.withReadyAuth(async () => {
      const fulfilled = outcomes.find((item) => item.status === 'fulfilled');
      if (fulfilled?.status !== 'fulfilled') throw new Error('missing reservation');
      expect((await f.fresh().read(fulfilled.value.reference)).attemptId).toBe(fulfilled.value.attemptId);
    });
  });

  it('replaces expired pending only while empty and never lets the old reference adopt the new attempt', async () => {
    const f = await fixture();
    const first = await f.coordinator.begin(input);
    f.setTime(START + 600_000);
    const next = await f.fresh().begin(input);
    expect(next.reference).not.toBe(first.reference);
    expect(next.attemptId).not.toBe(first.attemptId);
    await expect(f.fresh().read(first.reference)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('freezes exactly one user, consumed factor step and displayed backup hashes; applied replay never resets them', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin({ ...input, profile: PROFILE });
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    const receipt = await f.coordinator.complete({ reference: setup.reference, token: f.token(setup) });
    expect(f.current.users).toHaveLength(1);
    expect(f.current.users[0]).toMatchObject({ id: receipt.userId, role: 'super_admin', isActive: true, needsOnboarding: false, passwordHash: HASH });
    expect(f.current.factor).toMatchObject({ userId: receipt.userId, lastUsedTotpStep: STEP });
    expect(f.current.codes!.codes.map((code) => code.hash)).toEqual(setup.backupCodes.map(hashBackupCode));
    expect(f.current.profile).toEqual(PROFILE);
    f.current.codes!.codes[0].used = true;
    f.current.factor!.lastUsedTotpStep = STEP + 1;
    f.setTime(START + 600_001);
    await f.fresh().recover();
    expect(await f.fresh().complete({ reference: setup.reference, token: 'invalid' })).toEqual(receipt);
    expect(f.project).toHaveBeenCalledTimes(1);
    expect(f.current.codes!.codes[0].used).toBe(true);
    expect(f.current.factor!.lastUsedTotpStep).toBe(STEP + 1);
    expect((await f.read()).record.state).toBe('applied');
    expect(JSON.stringify(await f.read())).not.toContain(HASH);
    await expect(f.fresh().read(setup.reference)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    await expect(f.fresh().complete({ reference: '0'.repeat(64), token: f.token(setup) })).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    f.current.users = [];
    await expect(f.fresh().begin(input)).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it.each(['factor', 'codes', 'profile', 'user'] as const)('recovers after %s projection failure without a live browser proof', async (stage) => {
    const f = await fixture();
    const setup = await f.coordinator.begin({ ...input, profile: PROFILE });
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    f.failAfter(stage);
    await expect(f.coordinator.complete({ reference: setup.reference, token: f.token(setup) })).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    const frozen = (await f.read()).record;
    expect(frozen.state).toBe('committed');
    expect(JSON.stringify(frozen)).not.toContain(setup.secret);
    for (const code of setup.backupCodes) expect(JSON.stringify(frozen)).not.toContain(code);
    f.setTime(START + 86_400_000);
    f.failAfter();
    await f.fresh().recover();
    expect((await f.read()).record.state).toBe('applied');
    expect(f.current.users[0].id).toBe(frozen.completion.user.id);
    expect(f.completionGate).toHaveBeenCalledTimes(1);
  });

  it('preserves used codes and increasing counters during committed replay', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(input);
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    f.failAfter('user');
    await expect(f.coordinator.complete({ reference: setup.reference, token: f.token(setup) })).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    f.current.codes!.codes[0].used = true;
    f.current.factor!.lastUsedTotpStep = STEP + 10;
    f.failAfter();
    await f.fresh().recover();
    expect(f.current.codes!.codes[0].used).toBe(true);
    expect(f.current.factor!.lastUsedTotpStep).toBe(STEP + 10);
  });

  it('rechecks competing user creation after token verification and never writes over it', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(input);
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    f.completionGate.mockImplementationOnce(async () => {
      f.current.users = [{ id: 'github-user', handle: 'github-admin' } as AdminUser];
    });
    await expect(f.coordinator.complete({ reference: setup.reference, token: f.token(setup) })).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(f.project).not.toHaveBeenCalled();
    expect((await f.read()).record.state).toBe('pending');
  });

  it.each(['user', 'factor', 'codes'] as const)('keeps recovery closed on conflicting %s material', async (kind) => {
    const f = await fixture();
    const setup = await f.coordinator.begin(input);
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    f.failAfter('user');
    await expect(f.coordinator.complete({ reference: setup.reference, token: f.token(setup) })).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    if (kind === 'user') f.current.users[0].passwordHash = '$2b$04$' + 'B'.repeat(53);
    if (kind === 'factor') f.current.factor!.userId = 'another-user';
    if (kind === 'codes') f.current.codes!.codes[0].hash = 'f'.repeat(64);
    f.failAfter();
    await expect(f.fresh().recover()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    expect(f.project).toHaveBeenCalledTimes(1);
    expect((await f.read()).record.state).toBe('committed');
  });

  it('denies invalid token or expiry during verification without publishing commit', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(input);
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    await expect(f.coordinator.complete({ reference: setup.reference, token: f.wrongToken(setup) })).rejects.toMatchObject({ code: 'INVALID' });
    // A code that is genuinely valid at the deadline, verified after the clock crosses it.
    f.completionGate.mockImplementationOnce(async () => { f.setTime(START + 600_000); });
    await expect(f.coordinator.complete({ reference: setup.reference, token: f.token(setup, START + 600_000) })).rejects.toMatchObject({ code: 'EXPIRED' });
    expect(f.project).not.toHaveBeenCalled();
    expect((await f.read()).record.state).toBe('pending');
  });

  it('fails closed on wrong key, wrong authenticated scope/domain, altered ciphertext and malformed records', async () => {
    const f = await fixture();
    await f.coordinator.begin(input);
    const original = await fs.readFile(f.filename, 'utf8');
    const authenticated = await f.read();
    const wrongKey = new TOTPService({ encryptionKey: 'wrong-test-key', issuer: 'Bootstrap Test' });
    await expect(f.fresh({ totp: wrongKey }).recover()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    await expect(f.fresh({ scope: 'another-installation' }).recover()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    await f.write({ ...authenticated, domain: 'totp-secret' });
    await expect(f.fresh().recover()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    await f.write({ ...authenticated, record: { ...authenticated.record, role: 'super_admin' } });
    await expect(f.fresh().recover()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    const altered = JSON.parse(original);
    altered.encrypted.tag = Buffer.alloc(16).toString('base64');
    await fs.writeFile(f.filename, JSON.stringify(altered));
    await expect(f.fresh().recover()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    expect(f.project).not.toHaveBeenCalled();
    await fs.writeFile(f.filename, original);
    await expect(f.fresh().recover()).resolves.toBeUndefined();
  });

  it('does not disclose setup when pending publication finishes after expiry', async () => {
    const f = await fixture();
    const rename = fs.rename.bind(fs);
    vi.spyOn(fs, 'rename').mockImplementationOnce(async (source, destination) => {
      await rename(source, destination);
      f.setTime(START + 600_000);
    });
    await expect(f.coordinator.begin(input)).rejects.toMatchObject({ code: 'EXPIRED' });
    expect((await f.read()).record.state).toBe('pending');
    expect(f.project).not.toHaveBeenCalled();
  });

  it('never projects an unacknowledged commit; a rename-success exception is recoverable', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(input);
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    const rename = fs.rename.bind(fs);
    vi.spyOn(fs, 'rename').mockImplementationOnce(async (source, destination) => {
      await rename(source, destination);
      throw new Error('injected interruption after committed rename');
    });
    await expect(f.coordinator.complete({ reference: setup.reference, token: f.token(setup) })).rejects.toThrow('injected interruption');
    expect(f.project).not.toHaveBeenCalled();
    expect((await f.read()).record.state).toBe('committed');
    await f.fresh().recover();
    expect(f.current.users).toHaveLength(1);
  });

  it('retains pending when publication fails before commit rename', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(input);
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    vi.spyOn(fs, 'rename').mockRejectedValueOnce(new Error('injected rename failure'));
    await expect(f.coordinator.complete({ reference: setup.reference, token: f.token(setup) })).rejects.toThrow('injected rename failure');
    expect((await f.read()).record.state).toBe('pending');
    expect(f.project).not.toHaveBeenCalled();
    expect((await fs.readdir(f.directory))).toEqual(['bootstrap.json']);
  });

  it('does not publish pending when the temporary file cannot be synced', async () => {
    const f = await fixture();
    const open = fs.open.bind(fs);
    vi.spyOn(fs, 'open').mockImplementation(async (filename, flags, mode) => {
      const file = await open(filename, flags, mode);
      if (String(filename).endsWith('.tmp')) vi.spyOn(file, 'sync').mockRejectedValueOnce(new Error('temporary sync failure'));
      return file;
    });
    await expect(f.coordinator.begin(input)).rejects.toThrow('temporary sync failure');
    expect(await fs.readdir(f.directory)).toEqual([]);
    expect(f.project).not.toHaveBeenCalled();
  });

  it('acknowledges an uncertain pending directory sync before later admission, without disclosing setup', async () => {
    const f = await fixture();
    await fs.mkdir(f.directory, { mode: 0o700 });
    const open = fs.open.bind(fs);
    let failSync = true;
    vi.spyOn(fs, 'open').mockImplementation(async (filename, flags, mode) => {
      const file = await open(filename, flags, mode);
      if (String(filename) === f.directory && failSync) vi.spyOn(file, 'sync').mockRejectedValueOnce(new Error('directory sync failure'));
      return file;
    });
    await expect(f.coordinator.begin(input)).rejects.toThrow('directory sync failure');
    expect((await f.read()).record.state).toBe('pending');
    await expect(f.fresh().recover()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    failSync = false;
    await expect(f.fresh().recover()).resolves.toBeUndefined();
    expect(f.project).not.toHaveBeenCalled();
    await expect(f.fresh().begin(input)).rejects.toMatchObject({ code: 'CONFLICT' });
  });
});

describe('RS6: the first-admin coordinator verifies the code itself', () => {
  const alwaysValid = async () => ({ valid: true, step: 1 });
  const thrown = (operation: () => unknown): unknown => {
    try { operation(); } catch (error) { return error; }
    throw new Error('expected the constructor to refuse');
  };

  async function readyAttempt(f: Awaited<ReturnType<typeof fixture>>, coordinator = f.coordinator) {
    const setup = await coordinator.begin(input);
    await coordinator.acknowledgeBackupCodes(setup.reference);
    return setup;
  }

  it('refuses a structural TOTP look-alike, a subclass and an overridden instance at construction', async () => {
    const f = await fixture();
    const real = f.totp;
    const lookAlike = {
      generateSecret: real.generateSecret.bind(real),
      generateQRCode: real.generateQRCode.bind(real),
      encrypt: real.encrypt.bind(real),
      decrypt: real.decrypt.bind(real),
      verifyTokenWithStep: alwaysValid,
    };
    class AlwaysValid extends TOTPService {
      override async verifyTokenWithStep() { return { valid: true, step: 1 }; }
    }
    const subclass = new AlwaysValid({ encryptionKey: 'test-only-bootstrap-key-never-use-in-deployment', issuer: 'x' });
    const overridden = new TOTPService({ encryptionKey: 'test-only-bootstrap-key-never-use-in-deployment', issuer: 'x' });
    vi.spyOn(overridden, 'verifyTokenWithStep').mockImplementation(alwaysValid);
    const pinned = new TOTPService({ encryptionKey: 'test-only-bootstrap-key-never-use-in-deployment', issuer: 'x' });
    Object.defineProperty(pinned, 'generateSecret', { value: async (handle: string) => ({ handle, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', createdAt: new Date(START) }) });
    const reprototyped = Object.setPrototypeOf(new TOTPService({ encryptionKey: 'k', issuer: 'x' }), { ...lookAlike });
    for (const totp of [lookAlike, subclass, overridden, pinned, reprototyped, Object.create(real), null, undefined, {}]) {
      expect(thrown(() => f.fresh({ totp: totp as never }))).toMatchObject({ name: 'BootstrapJournalError', code: 'INVALID' });
      expect(thrown(() => new FileTotpEnrollmentCoordinator({
        directory: path.join(f.root, 'enrollment'), totp: totp as never,
        loadCurrent: async () => { throw new Error('Unused'); }, project: async () => { throw new Error('Unused'); },
      }))).toMatchObject({ name: 'TotpEnrollmentError', code: 'INVALID' });
    }
    expect(f.project).not.toHaveBeenCalled();
    expect(f.current.users).toEqual([]);
  });

  it('ignores verifier patches made after construction: instance, prototype and config object', async () => {
    const f = await fixture();
    const coordinator = f.fresh();
    const setup = await readyAttempt(f, coordinator);
    // Every later route an attacker-controlled caller has to the verifier.
    Object.defineProperty(f.totp, 'verifyTokenWithStep', { value: alwaysValid, configurable: true });
    Object.defineProperty(f.totp, 'generateSecret', { value: async () => ({ handle: 'x', secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', createdAt: new Date() }), configurable: true });
    vi.spyOn(TOTPService.prototype, 'verifyTokenWithStep').mockImplementation(alwaysValid);
    (coordinator as unknown as { config: FileBootstrapConfig }).config.totp = { verifyTokenWithStep: alwaysValid } as never;
    // The bound primitives are native #private fields, and (W8 r3) the instance
    // is frozen, so an own property cannot even be added.
    expect(() => Object.assign(coordinator, { totp: { verifyTokenWithStep: alwaysValid }, beforeComplete: alwaysValid })).toThrow(TypeError);
    await expect(coordinator.complete({ reference: setup.reference, token: f.wrongToken(setup) })).rejects.toMatchObject({ code: 'INVALID' });
    expect(f.project).not.toHaveBeenCalled();
    expect(f.current.users).toEqual([]);
    expect((await f.read()).record.state).toBe('pending');
    // Non-vacuous: the genuine code still completes through the same coordinator.
    await expect(coordinator.complete({ reference: setup.reference, token: f.token(setup) })).resolves.toMatchObject({ handle: 'first-admin' });
    expect(f.current.users).toMatchObject([{ handle: 'first-admin', role: 'super_admin' }]);
  });

  it('ignores patches of the captured method functions and of the deny hook own call (W8 r2)', async () => {
    const f = await fixture();
    const coordinator = f.fresh();
    const setup = await readyAttempt(f, coordinator);
    const forged = async () => ({ valid: true, step: 1 });
    for (const name of AUTHORITY_METHODS) expect(Object.isFrozen(ORIGINAL_METHODS[name])).toBe(true);
    // The r1 fix ran `method.call(service, ...)`: either patch below then minted super_admin.
    expect(() => Object.defineProperty(ORIGINAL_METHODS.verifyTokenWithStep, 'call', { value: forged })).toThrow(TypeError);
    expect(() => Object.setPrototypeOf(ORIGINAL_METHODS.verifyTokenWithStep, { call: forged, apply: forged })).toThrow(TypeError);
    expect(() => Object.defineProperty(ORIGINAL_METHODS.generateSecret, 'call', { value: forged })).toThrow(TypeError);
    await expect(coordinator.complete({ reference: setup.reference, token: f.wrongToken(setup) })).rejects.toMatchObject({ code: 'INVALID' });
    // A denying hook still denies when its own `call` is replaced.
    class WritesClosed extends Error { readonly status = 503; }
    const closed = new WritesClosed('authority writes are paused');
    Object.defineProperty(f.completionGate, 'call', { value: async () => undefined, configurable: true });
    f.completionGate.mockRejectedValueOnce(closed);
    await expect(coordinator.complete({ reference: setup.reference, token: f.token(setup) })).rejects.toBe(closed);
    expect(f.project).not.toHaveBeenCalled();
    expect(f.current.users).toEqual([]);
    expect((await f.read()).record.state).toBe('pending');
    // Non-vacuous: the genuine code still completes through the same coordinator.
    await expect(coordinator.complete({ reference: setup.reference, token: f.token(setup) })).resolves.toMatchObject({ handle: 'first-admin' });
    expect(f.current.users).toMatchObject([{ handle: 'first-admin', role: 'super_admin' }]);
  });

  it('freezes the exported authority classes, their prototypes and their instances (W8 r3)', async () => {
    const f = await fixture();
    const coordinator = f.fresh();
    const setup = await readyAttempt(f, coordinator);
    for (const authority of [FileBootstrapCoordinator, FileTotpEnrollmentCoordinator, FileTotpRetirementCoordinator, FileActionStepUpStore]) {
      expect(Object.isFrozen(authority)).toBe(true);
      expect(Object.isFrozen(authority.prototype)).toBe(true);
    }
    expect(Object.isFrozen(coordinator)).toBe(true);
    expect(Object.isFrozen(f.gate)).toBe(true);
    // Security lens r5: wrapping the TypeScript-private `pending` on the exported
    // prototype swapped the enrolment seed, and that seed's code then minted
    // super_admin with the attacker seed stored as the factor.
    const ATTACKER_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXQ';
    type Method = (...args: unknown[]) => Promise<Record<string, unknown>>;
    const prototype = FileBootstrapCoordinator.prototype as unknown as Record<string, Method>;
    const pending = prototype.pending;
    const swapSeed: Method = async function (this: unknown, ...args: unknown[]) {
      return { ...(await Reflect.apply(pending, this, args)), secret: ATTACKER_SECRET };
    };
    expect(() => { prototype.pending = swapSeed; }).toThrow(TypeError);
    expect(() => Object.defineProperty(prototype, 'pending', { value: swapSeed })).toThrow(TypeError);
    expect(() => { prototype.bind = async () => ({}); }).toThrow(TypeError);
    expect(() => Object.defineProperty(coordinator, 'pending', { value: swapSeed })).toThrow(TypeError);
    expect(() => Object.setPrototypeOf(coordinator, { complete: async () => ({}) })).toThrow(TypeError);
    expect(() => Object.setPrototypeOf(FileBootstrapCoordinator.prototype, {})).toThrow(TypeError);
    expect(prototype.pending).toBe(pending);
    await expect(coordinator.complete({ reference: setup.reference, token: f.token({ secret: ATTACKER_SECRET }) })).rejects.toMatchObject({ code: 'INVALID' });
    expect(f.project).not.toHaveBeenCalled();
    expect(f.current.users).toEqual([]);
    // Non-vacuous: the genuine code still completes, and the stored factor is the coordinator's own seed.
    await expect(coordinator.complete({ reference: setup.reference, token: f.token(setup) })).resolves.toMatchObject({ handle: 'first-admin' });
    expect(f.current.users).toMatchObject([{ handle: 'first-admin', role: 'super_admin' }]);
    const factor = f.current.factor!;
    expect(f.totp.decrypt({ encrypted: factor.encryptedSecret, iv: factor.iv, tag: factor.authTag, salt: factor.salt })).toBe(setup.secret);
  });

  it('beforeComplete can only deny: its result never accepts a code, and its error refuses a valid one', async () => {
    const f = await fixture();
    const setup = await readyAttempt(f);
    for (const affirmation of [true, { valid: true, step: 1 }, 'accept']) {
      f.completionGate.mockImplementationOnce(async () => affirmation as never);
      await expect(f.coordinator.complete({ reference: setup.reference, token: f.wrongToken(setup) })).rejects.toMatchObject({ code: 'INVALID' });
    }
    class WritesClosed extends Error { readonly status = 503; }
    const closed = new WritesClosed('authority writes are paused');
    f.completionGate.mockImplementationOnce(() => { throw closed; });
    await expect(f.coordinator.complete({ reference: setup.reference, token: f.token(setup) })).rejects.toBe(closed);
    f.completionGate.mockRejectedValueOnce(closed);
    await expect(f.coordinator.complete({ reference: setup.reference, token: f.token(setup) })).rejects.toBe(closed);
    expect(f.completionGate).toHaveBeenCalledWith('bootstrap.complete');
    expect(f.project).not.toHaveBeenCalled();
    expect((await f.read()).record).toMatchObject({ state: 'pending', backupCodesAcknowledged: true });
    const receipt = await f.coordinator.complete({ reference: setup.reference, token: f.token(setup) });
    expect(f.current.users).toMatchObject([{ handle: 'first-admin', role: 'super_admin' }]);
    // Applied replay returns before the gate, so a closed gate never blocks history.
    const calls = f.completionGate.mock.calls.length;
    f.completionGate.mockImplementation(() => { throw closed; });
    await expect(f.fresh().complete({ reference: setup.reference, token: 'invalid' })).resolves.toEqual(receipt);
    expect(f.completionGate).toHaveBeenCalledTimes(calls);
  });

  it('rejects a non-function beforeComplete', async () => {
    const f = await fixture();
    expect(thrown(() => f.fresh({ beforeComplete: 'allow' as never }))).toMatchObject({ code: 'INVALID' });
  });
});
