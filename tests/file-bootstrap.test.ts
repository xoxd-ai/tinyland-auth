import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { TOTPService } from '../src/core/totp/index.js';
import { hashBackupCode } from '../src/core/backup-codes/index.js';
import { FileBootstrapCoordinator, type BootstrapCompletion, type FileBootstrapConfig } from '../src/storage/file-bootstrap.js';
import { FileTotpEnrollmentCoordinator } from '../src/storage/file-totp-enrollment.js';
import type { AdminUser, BackupCodeSet, EncryptedData, EncryptedTOTPSecret } from '../src/types/auth.js';

const START = Date.parse('2026-09-24T02:00:00.000Z');
const HASH = '$2b$04$' + 'A'.repeat(53);
const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
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
  vi.spyOn(totp, 'generateSecret').mockImplementation(async (handle) => ({ handle, secret: SECRET, qrCodeUrl: 'data:test', createdAt: new Date(time) }));
  vi.spyOn(totp, 'generateQRCode').mockResolvedValue('data:test');
  vi.spyOn(totp, 'verifyTokenWithStep').mockResolvedValue({ valid: true, step: 50 });
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
    directory, scope: 'test-installation', totp, storage, project,
    withExclusiveAuth: (operation) => gate.withReadyAuth(operation),
    now: () => new Date(time), ...overrides,
  };
  const fresh = (options: Partial<FileBootstrapConfig> = {}) => new FileBootstrapCoordinator({ ...config, ...options });
  const read = async () => {
    const envelope = JSON.parse(await fs.readFile(filename, 'utf8')) as { version: number; encrypted: EncryptedData };
    return JSON.parse(totp.decrypt(envelope.encrypted));
  };
  const write = async (value: unknown) => fs.writeFile(filename, JSON.stringify({ version: 1, encrypted: totp.encrypt(JSON.stringify(value)) }));
  return { root, directory, filename, totp, storage, current, project, gate, fresh, coordinator: fresh(), read, write,
    setTime: (value: number) => { time = value; }, failAfter: (value?: typeof failAfter) => { failAfter = value; } };
}

describe('encrypted durable bootstrap coordinator', () => {
  it('normalizes a new uppercase handle across setup, journal, factor and frozen profile owner', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin({ ...input, handle: '  First-ADMIN  ', profile: PROFILE });
    expect(setup.handle).toBe('first-admin');
    expect(f.totp.generateSecret).toHaveBeenCalledWith('first-admin');
    expect(vi.mocked(f.totp.generateQRCode).mock.calls[0][0].handle).toBe('first-admin');
    const pending = (await f.read()).record;
    expect(pending.handle).toBe('first-admin');
    expect((await f.fresh().read(setup.reference)).handle).toBe('first-admin');
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    const receipt = await f.coordinator.complete({ reference: setup.reference, token: '123456' });
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
    const receipt = await f.coordinator.complete({ reference: setup.reference, token: '123456' });
    expect(receipt.handle).toBe('7admin');
    expect(f.current.users[0].handle).toBe('7admin');
    expect(f.current.factor!.handle).toBe('7admin');
  });

  it('rejects an underscore initial character before generating or writing setup material', async () => {
    const f = await fixture();
    await expect(f.coordinator.begin({ ...input, handle: '_admin' })).rejects.toMatchObject({ code: 'INVALID' });
    expect(f.totp.generateSecret).not.toHaveBeenCalled();
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
    for (const secret of [HASH, SECRET, input.handle, setup.reference, PROFILE.bio, ...setup.backupCodes]) expect(raw).not.toContain(secret);
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
    await expect(f.coordinator.complete({ reference: setup.reference, token: '123456' })).rejects.toMatchObject({ code: 'INVALID' });
    expect(f.totp.verifyTokenWithStep).not.toHaveBeenCalled();
    expect(f.project).not.toHaveBeenCalled();
    await expect(f.coordinator.acknowledgeBackupCodes('0'.repeat(64))).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect((await f.read()).record.backupCodesAcknowledged).toBe(false);
    await f.fresh().acknowledgeBackupCodes(setup.reference);
    expect((await f.read()).record.backupCodesAcknowledged).toBe(true);
    await f.fresh().updateProfile(setup.reference, PROFILE);
    await f.fresh().acknowledgeBackupCodes(setup.reference);
    expect(await f.fresh().read(setup.reference)).toEqual({ ...setup, profile: PROFILE, backupCodesAcknowledged: true });
    await expect(f.fresh().complete({ reference: setup.reference, token: '123456' })).resolves.toMatchObject({ handle: input.handle });
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
    await expect(f.fresh().complete({ reference: replacement.reference, token: '123456' })).rejects.toMatchObject({ code: 'INVALID' });
    expect(f.project).not.toHaveBeenCalled();
  });

  it('retains unacknowledged pending when acknowledgment publication fails', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(input);
    vi.spyOn(fs, 'rename').mockRejectedValueOnce(new Error('ack publication failed'));
    await expect(f.coordinator.acknowledgeBackupCodes(setup.reference)).rejects.toThrow('ack publication failed');
    expect((await f.read()).record.backupCodesAcknowledged).toBe(false);
    await expect(f.fresh().complete({ reference: setup.reference, token: '123456' })).rejects.toMatchObject({ code: 'INVALID' });
  });

  it('rejects a retained namespace before generating setup and rechecks after asynchronous generation', async () => {
    const namespace = vi.fn(async (): Promise<void> => { throw new Error('private namespace path must not escape'); });
    const f = await fixture({ assertNamespaceAvailable: namespace });
    await expect(f.coordinator.begin(input)).rejects.toMatchObject({ code: 'CONFLICT', message: 'Bootstrap state requires review or is unavailable' });
    expect(f.totp.generateSecret).not.toHaveBeenCalled();
    expect(await fs.readdir(f.root)).toEqual(['enrollment']);
    namespace.mockResolvedValueOnce(undefined);
    await expect(f.fresh().begin(input)).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(f.totp.generateSecret).toHaveBeenCalledOnce();
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
    vi.mocked(f.totp.verifyTokenWithStep).mockImplementationOnce(async () => {
      namespaceOccupied = true;
      return { valid: true, step: 50 };
    });
    await expect(coordinator.complete({ reference: setup.reference, token: '123456' })).rejects.toMatchObject({ code: 'CONFLICT' });
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
    await expect(f.coordinator.complete({ reference: setup.reference, token: '123456' })).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
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
    await expect(f.fresh().complete({ reference: setup.reference, token: '123456' })).rejects.toMatchObject({ code: 'EXPIRED' });
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
    const receipt = await f.coordinator.complete({ reference: setup.reference, token: '123456' });
    expect(f.current.users).toHaveLength(1);
    expect(f.current.users[0]).toMatchObject({ id: receipt.userId, role: 'super_admin', isActive: true, needsOnboarding: false, passwordHash: HASH });
    expect(f.current.factor).toMatchObject({ userId: receipt.userId, lastUsedTotpStep: 50 });
    expect(f.current.codes!.codes.map((code) => code.hash)).toEqual(setup.backupCodes.map(hashBackupCode));
    expect(f.current.profile).toEqual(PROFILE);
    f.current.codes!.codes[0].used = true;
    f.current.factor!.lastUsedTotpStep = 51;
    f.setTime(START + 600_001);
    await f.fresh().recover();
    expect(await f.fresh().complete({ reference: setup.reference, token: 'invalid' })).toEqual(receipt);
    expect(f.project).toHaveBeenCalledTimes(1);
    expect(f.current.codes!.codes[0].used).toBe(true);
    expect(f.current.factor!.lastUsedTotpStep).toBe(51);
    expect((await f.read()).record.state).toBe('applied');
    expect(JSON.stringify(await f.read())).not.toContain(HASH);
    await expect(f.fresh().read(setup.reference)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    await expect(f.fresh().complete({ reference: '0'.repeat(64), token: '123456' })).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    f.current.users = [];
    await expect(f.fresh().begin(input)).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it.each(['factor', 'codes', 'profile', 'user'] as const)('recovers after %s projection failure without a live browser proof', async (stage) => {
    const f = await fixture();
    const setup = await f.coordinator.begin({ ...input, profile: PROFILE });
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    f.failAfter(stage);
    await expect(f.coordinator.complete({ reference: setup.reference, token: '123456' })).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    const frozen = (await f.read()).record;
    expect(frozen.state).toBe('committed');
    expect(JSON.stringify(frozen)).not.toContain(SECRET);
    for (const code of setup.backupCodes) expect(JSON.stringify(frozen)).not.toContain(code);
    f.setTime(START + 86_400_000);
    f.failAfter();
    await f.fresh().recover();
    expect((await f.read()).record.state).toBe('applied');
    expect(f.current.users[0].id).toBe(frozen.completion.user.id);
    expect(f.totp.verifyTokenWithStep).toHaveBeenCalledTimes(1);
  });

  it('preserves used codes and increasing counters during committed replay', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(input);
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    f.failAfter('user');
    await expect(f.coordinator.complete({ reference: setup.reference, token: '123456' })).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    f.current.codes!.codes[0].used = true;
    f.current.factor!.lastUsedTotpStep = 60;
    f.failAfter();
    await f.fresh().recover();
    expect(f.current.codes!.codes[0].used).toBe(true);
    expect(f.current.factor!.lastUsedTotpStep).toBe(60);
  });

  it('rechecks competing user creation after token verification and never writes over it', async () => {
    const f = await fixture();
    const setup = await f.coordinator.begin(input);
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    vi.mocked(f.totp.verifyTokenWithStep).mockImplementationOnce(async () => {
      f.current.users = [{ id: 'github-user', handle: 'github-admin' } as AdminUser];
      return { valid: true, step: 50 };
    });
    await expect(f.coordinator.complete({ reference: setup.reference, token: '123456' })).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(f.project).not.toHaveBeenCalled();
    expect((await f.read()).record.state).toBe('pending');
  });

  it.each(['user', 'factor', 'codes'] as const)('keeps recovery closed on conflicting %s material', async (kind) => {
    const f = await fixture();
    const setup = await f.coordinator.begin(input);
    await f.coordinator.acknowledgeBackupCodes(setup.reference);
    f.failAfter('user');
    await expect(f.coordinator.complete({ reference: setup.reference, token: '123456' })).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
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
    vi.mocked(f.totp.verifyTokenWithStep).mockResolvedValueOnce({ valid: false });
    await expect(f.coordinator.complete({ reference: setup.reference, token: '123456' })).rejects.toMatchObject({ code: 'INVALID' });
    vi.mocked(f.totp.verifyTokenWithStep).mockImplementationOnce(async () => { f.setTime(START + 600_000); return { valid: true, step: 50 }; });
    await expect(f.coordinator.complete({ reference: setup.reference, token: '123456' })).rejects.toMatchObject({ code: 'EXPIRED' });
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
    await expect(f.coordinator.complete({ reference: setup.reference, token: '123456' })).rejects.toThrow('injected interruption');
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
    await expect(f.coordinator.complete({ reference: setup.reference, token: '123456' })).rejects.toThrow('injected rename failure');
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
