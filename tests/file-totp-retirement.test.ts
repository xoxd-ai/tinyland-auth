import { promises as fs } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createHash, createHmac } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FileStorageAdapter } from '../src/storage/file.js';
import { FileTotpEnrollmentCoordinator } from '../src/storage/file-totp-enrollment.js';
import {
  FileTotpRetirementCoordinator, type FileTotpRetirementConfig,
  type TotpRetirementConsumedAuthorization,
} from '../src/storage/file-totp-retirement.js';
import { totpRetirementFactorGeneration, totpRetirementFactorSnapshotDigest,
  totpRetirementRecoverySetDigest } from '../src/storage/totp-retirement-material.js';
import type { BackupCodeSet, EncryptedTOTPSecret } from '../src/types/auth.js';

const directories: string[] = [];
const NOW = Date.parse('2026-09-24T12:00:00.000Z');
const KEY = 'fixture-retirement-signing-key-at-least-32-bytes';
afterEach(async () => {
  vi.restoreAllMocks();
  for (const directory of directories.splice(0)) await fs.rm(directory, { recursive: true, force: true });
});
async function fixture() {
  const directory = await fs.realpath(await fs.mkdtemp(path.join(tmpdir(), 'tinyland-retirement-')));
  directories.push(directory);
  const authDir = path.join(directory, 'auth'); const factorDir = path.join(directory, 'factors');
  const storage = new FileStorageAdapter({ authDir: path.relative(process.cwd(), authDir), totpDir: path.relative(process.cwd(), factorDir) });
  await storage.init();
  const user = await storage.createUser({ handle: 'alice', passwordHash: 'fixture-password-hash', role: 'member',
    isActive: true, needsOnboarding: false, onboardingStep: 3, firstLogin: false,
    totpEnabled: true, totpSecretId: 'alice', createdAt: new Date(NOW - 1000).toISOString(), updatedAt: new Date(NOW).toISOString() });
  const factor: EncryptedTOTPSecret = { userId: user.id, handle: user.handle, encryptedSecret: 'fixture-encrypted-factor',
    iv: 'fixture-iv', authTag: 'fixture-tag', salt: 'fixture-salt', version: 1,
    backupCodesGenerated: true, createdAt: new Date(NOW - 1000).toISOString(), lastUsedTotpStep: 10 };
  const codes: BackupCodeSet = { userId: user.id, generatedAt: new Date(NOW - 1000).toISOString(),
    codes: [{ id: 'fixture-code', hash: 'a'.repeat(64), used: false }] };
  await storage.saveTOTPSecret(user.handle, factor); await storage.saveBackupCodes(user.id, codes);
  const session = await storage.createSession(user.id, user);
  await storage.updateSession(session.id, { createdAt: new Date(NOW - 1000).toISOString(),
    expires: new Date(NOW + 60_000).toISOString(), expiresAt: new Date(NOW + 60_000).toISOString() });
  const enrollmentDir = path.join(directory, 'enrollment');
  const enrollment = new FileTotpEnrollmentCoordinator({ directory: enrollmentDir,
    totp: { generateSecret: vi.fn(), generateQRCode: vi.fn(), encrypt: vi.fn(), decrypt: vi.fn(), verifyTokenWithStep: vi.fn() },
    loadCurrent: async binding => ({ user: await storage.getUser(binding.userId), session: await storage.getSession(binding.sessionId),
      totpSecret: await storage.getTOTPSecret(user.handle), backupCodes: await storage.getBackupCodes(binding.userId) }),
    project: async () => { throw new Error('Enrollment projection not used by retirement'); } });
  let clock = NOW;
  const journal = path.join(directory, 'retirement');
  const config: FileTotpRetirementConfig = { directory: journal, storage, signingKey: () => KEY,
    now: () => clock, withExclusiveAuth: operation => enrollment.withReadyAuth(operation) };
  const coordinator = new FileTotpRetirementCoordinator(config);
  const consumed: TotpRetirementConsumedAuthorization = { kind: 'consumed', receiptId: 'r'.repeat(43),
    actorId: user.id, action: 'factor.disable', resourceId: user.id, factorBinding: 'b'.repeat(64) };
  const binding = { userId: user.id, handle: user.handle, sessionId: session.id };
  const authorize = vi.fn(async () => ({ ...consumed }));
  const retire = () => coordinator.retire({ ...binding, authorize });
  return { directory, authDir, factorDir, user, factor, codes, session, enrollmentDir, enrollment, storage,
    journal, config, coordinator, consumed, binding, authorize, retire, setClock: (value: number) => { clock = value; } };
}
async function assertRetired(f: Awaited<ReturnType<typeof fixture>>) {
  expect(await f.storage.getTOTPSecret(f.user.handle)).toBeNull();
  expect(await f.storage.getBackupCodes(f.user.id)).toBeNull();
  expect(await f.storage.getSessionsByUser(f.user.id)).toEqual([]);
  expect(await f.storage.getUser(f.user.id)).toMatchObject({ id: f.user.id, handle: f.user.handle, role: 'member', totpEnabled: false });
  expect((await f.storage.getUser(f.user.id))?.totpSecretId).toBeUndefined();
}

describe('restart-durable factor retirement', () => {
  it('returns challenge/denial without revocation, credential writes or authority journal', async () => {
    const f = await fixture(); const revoke = vi.spyOn(f.storage, 'deleteUserSessions');
    const result = await f.coordinator.retire({ ...f.binding, authorize: async () => ({ kind: 'not-consumed', result: { status: 428 } }) });
    expect(result).toEqual({ kind: 'not-consumed', result: { status: 428 } });
    expect(revoke).not.toHaveBeenCalled(); expect(await fs.readdir(f.journal)).toEqual([]);
    expect(await f.storage.getTOTPSecret(f.user.handle)).toEqual(f.factor);
  });
  it('commits before effects, retires all projections and stores digests rather than credential material', async () => {
    const f = await fixture(); const original = f.storage.deleteUserSessions.bind(f.storage);
    vi.spyOn(f.storage, 'deleteUserSessions').mockImplementation(async id => {
      const names = await fs.readdir(f.journal);
      expect(names).toHaveLength(1);
      expect(JSON.parse(await fs.readFile(path.join(f.journal, names[0]), 'utf8')).record.state).toBe('committed');
      return original(id);
    });
    const result = await f.retire(); expect(result.kind).toBe('retired'); await assertRetired(f);
    const raw = await fs.readFile(path.join(f.journal, (await fs.readdir(f.journal))[0]), 'utf8');
    for (const secret of [f.factor.encryptedSecret, f.factor.salt, f.codes.codes[0].hash, f.session.id, f.consumed.receiptId]) expect(raw).not.toContain(secret);
    expect(await f.coordinator.readReceipt({ receiptId: f.consumed.receiptId, userId: f.user.id })).toMatchObject({ factorGeneration: totpRetirementFactorGeneration(f.factor) });
  });
  it('permits nested existing-gate authorization and counter advancement, but freezes the post-authorization snapshot', async () => {
    const f = await fixture();
    const result = await f.coordinator.retire({ ...f.binding, authorize: async context => f.enrollment.withReadyAuth(async () => {
      expect(context.factorGeneration).toBe(totpRetirementFactorGeneration(f.factor));
      await f.storage.saveTOTPSecret(f.user.handle, { ...f.factor, lastUsedTotpStep: 11, lastUsedAt: new Date(NOW).toISOString() });
      return f.consumed;
    }) });
    expect(result.kind).toBe('retired'); await assertRetired(f);
  });
  it.each(['factor', 'codes', 'session', 'principal', 'expiry'] as const)('rejects changed %s after authorization before commit', async change => {
    const f = await fixture();
    await expect(f.coordinator.retire({ ...f.binding, authorize: async () => {
      if (change === 'factor') await f.storage.saveTOTPSecret(f.user.handle, { ...f.factor, encryptedSecret: 'replacement' });
      if (change === 'codes') await f.storage.saveBackupCodes(f.user.id, { ...f.codes, codes: [{ ...f.codes.codes[0], used: true }] });
      if (change === 'session') await f.storage.deleteSession(f.session.id);
      if (change === 'principal') await f.storage.updateUser(f.user.id, { role: 'viewer' });
      if (change === 'expiry') f.setClock(NOW + 120_000);
      return f.consumed;
    } })).rejects.toThrow();
    expect(await fs.readdir(f.journal)).toEqual([]);
    expect(await f.storage.getTOTPSecret(f.user.handle)).not.toBeNull();
  });
  it.each(['actorId', 'resourceId', 'action', 'receiptId', 'factorBinding'] as const)('rejects malformed consumed %s with zero effects', async field => {
    const f = await fixture();
    await expect(f.coordinator.retire({ ...f.binding, authorize: async () => ({ ...f.consumed, [field]: 'wrong' }) as TotpRetirementConsumedAuthorization })).rejects.toThrow();
    expect(await fs.readdir(f.journal)).toEqual([]); expect(await f.storage.getSession(f.session.id)).not.toBeNull();
  });
  it.each(['deleteUserSessions', 'deleteTOTPSecretExpected', 'deleteBackupCodesExpected', 'clearTotpFlagsExpected'] as const)(
    'recovers after %s fails without another session, permit, or phase activation', async method => {
      const f = await fixture(); vi.spyOn(f.storage, method).mockRejectedValueOnce(new Error('injected storage fault'));
      await expect(f.retire()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
      expect(f.authorize).toHaveBeenCalledTimes(1);
      f.setClock(NOW + 86400_000);
      await new FileTotpRetirementCoordinator(f.config).recover(); await assertRetired(f);
      expect(f.authorize).toHaveBeenCalledTimes(1);
    });
  it('does not project when commit rename reports uncertain publication; restart acknowledges and recovers', async () => {
    const f = await fixture(); const rename = fs.rename.bind(fs); const revoke = vi.spyOn(f.storage, 'deleteUserSessions');
    vi.spyOn(fs, 'rename').mockImplementationOnce(async (from, to) => { await rename(from, to); throw new Error('after rename before directory sync'); });
    await expect(f.retire()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    expect(revoke).not.toHaveBeenCalled(); expect(await f.storage.getTOTPSecret(f.user.handle)).toEqual(f.factor);
    vi.restoreAllMocks(); await new FileTotpRetirementCoordinator(f.config).recover(); await assertRetired(f);
  });
  it.each([2, 3])('recovers publication directory-fsync failure at journal sync %s', async failAt => {
    const f = await fixture(); const open = fs.open.bind(fs); let syncs = 0;
    const revoke = vi.spyOn(f.storage, 'deleteUserSessions');
    vi.spyOn(fs, 'open').mockImplementation(async (...args: Parameters<typeof fs.open>) => {
      const handle = await open(...args);
      if (String(args[0]) === f.journal && ++syncs === failAt) {
        vi.spyOn(handle, 'sync').mockRejectedValueOnce(new Error('journal directory fsync fault'));
      }
      return handle;
    });
    await expect(f.retire()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    if (failAt === 2) {
      expect(revoke).not.toHaveBeenCalled(); expect(await f.storage.getTOTPSecret(f.user.handle)).toEqual(f.factor);
    } else await assertRetired(f);
    vi.restoreAllMocks(); const replayRevoke = vi.spyOn(f.storage, 'deleteUserSessions');
    await new FileTotpRetirementCoordinator(f.config).recover(); await assertRetired(f);
    if (failAt === 3) expect(replayRevoke).not.toHaveBeenCalled(); // Applied rename is acknowledged, never reprojected.
  });
  it('does not mark applied when a storage capability falsely acknowledges unchanged flags', async () => {
    const f = await fixture(); vi.spyOn(f.storage, 'clearTotpFlagsExpected').mockResolvedValueOnce();
    await expect(f.retire()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    expect(JSON.parse(await fs.readFile(path.join(f.journal, (await fs.readdir(f.journal))[0]), 'utf8')).record.state).toBe('committed');
    await f.coordinator.recover(); await assertRetired(f);
  });
  it('refuses replacement factor during committed recovery rather than deleting it', async () => {
    const f = await fixture(); vi.spyOn(f.storage, 'deleteTOTPSecretExpected').mockRejectedValueOnce(new Error('stop'));
    await expect(f.retire()).rejects.toThrow();
    const replacement = { ...f.factor, salt: 'different-generation' };
    await f.storage.saveTOTPSecret(f.user.handle, replacement);
    await expect(new FileTotpRetirementCoordinator(f.config).recover()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    expect(await f.storage.getTOTPSecret(f.user.handle)).toEqual(replacement);
  });
  it('applied history never removes later enrolled material; a fresh receipt can retire the later generation', async () => {
    const f = await fixture(); await f.retire();
    const next = { ...f.factor, salt: 'new-generation', lastUsedTotpStep: 11 };
    await f.storage.saveTOTPSecret(f.user.handle, next); await f.storage.saveBackupCodes(f.user.id, f.codes);
    await f.storage.updateUser(f.user.id, { totpEnabled: true, totpSecretId: f.user.handle });
    const session = await f.storage.createSession(f.user.id, f.user);
    await f.storage.updateSession(session.id, { createdAt: new Date(NOW).toISOString(), expires: new Date(NOW + 60_000).toISOString() });
    await f.coordinator.recover(); await f.coordinator.readReceipt({ receiptId: f.consumed.receiptId, userId: f.user.id });
    expect(await f.storage.getTOTPSecret(f.user.handle)).toEqual(next);
    await expect(f.coordinator.retire({ ...f.binding, sessionId: session.id, authorize: async () => f.consumed })).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(await f.storage.getTOTPSecret(f.user.handle)).toEqual(next);
    await f.coordinator.retire({ ...f.binding, sessionId: session.id, authorize: async () => ({ ...f.consumed, receiptId: 's'.repeat(43) }) });
    await assertRetired(f); expect(await fs.readdir(f.journal)).toHaveLength(2);
  });
  it('does not alter existing applied enrollment proof history', async () => {
    const f = await fixture();
    await fs.mkdir(f.enrollmentDir, { recursive: true });
    const attemptId = 'a'.repeat(48);
    const applied = { version: 2, mode: 'self-enrollment', state: 'applied', sessionDigest: 'b'.repeat(64),
      primaryReauthUses: [{ digest: 'c'.repeat(64), attemptId, expiresAt: new Date(NOW + 300_000).toISOString() }],
      receipt: { version: 2, mode: 'self-enrollment', attemptId, userId: f.user.id, handle: f.user.handle,
        completedAt: new Date(NOW - 1000).toISOString(), materialDigest: 'd'.repeat(64) } };
    const history = path.join(f.enrollmentDir, `${createHash('sha256').update(f.user.id).digest('hex')}.json`);
    const bytes = JSON.stringify(applied);
    await fs.writeFile(history, bytes); await f.retire();
    await f.coordinator.recover(); expect(await fs.readFile(history, 'utf8')).toBe(bytes);
  });
  it('rejects malformed or modified sealed journal before ordinary auth may proceed', async () => {
    const f = await fixture(); await f.retire();
    const filename = path.join(f.journal, (await fs.readdir(f.journal))[0]);
    const envelope = JSON.parse(await fs.readFile(filename, 'utf8')); envelope.record.receipt.userId = 'other';
    await fs.writeFile(filename, JSON.stringify(envelope));
    await expect(f.coordinator.recover()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
  });
  it.each(['factorGeneration', 'appliedAt', 'extra'] as const)('rejects structurally malformed %s even with correct seal', async field => {
    const f = await fixture(); await f.retire();
    const filename = path.join(f.journal, (await fs.readdir(f.journal))[0]);
    const envelope = JSON.parse(await fs.readFile(filename, 'utf8'));
    envelope.record.receipt[field] = field === 'factorGeneration' ? ['a'.repeat(64)] : 'invalid';
    envelope.seal = createHmac('sha256', KEY).update('tinyland-auth:totp-retirement:seal:v1\0').update(JSON.stringify(envelope.record)).digest('hex');
    await fs.writeFile(filename, JSON.stringify(envelope));
    await expect(f.coordinator.recover()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
  });
  it('fails closed on an unknown journal filename', async () => {
    const f = await fixture(); await f.coordinator.recover(); await fs.writeFile(path.join(f.journal, 'unknown.json'), '{}');
    await expect(f.retire()).rejects.toMatchObject({ code: 'RECOVERY_REQUIRED' });
    expect(f.authorize).not.toHaveBeenCalled();
  });
});

describe('file-only expected durable credential deletion', () => {
  it('rejects changed material, missing expected set, unsafe identity and hardlink without deleting', async () => {
    const f = await fixture();
    await expect(f.storage.deleteTOTPSecretExpected(f.user.handle, '0'.repeat(64))).rejects.toThrow();
    await expect(f.storage.deleteBackupCodesExpected(f.user.id, null)).rejects.toThrow();
    await expect(f.storage.deleteTOTPSecretExpected('../alice', totpRetirementFactorSnapshotDigest(f.factor))).rejects.toThrow();
    const filename = path.join(f.factorDir, 'alice.json'); await fs.link(filename, path.join(f.directory, 'alias'));
    await expect(f.storage.deleteTOTPSecretExpected(f.user.handle, totpRetirementFactorSnapshotDigest(f.factor))).rejects.toThrow();
    expect(await f.storage.getTOTPSecret(f.user.handle)).toEqual(f.factor);
  });
  it('acknowledges absent replay and deletes only exact recovery set', async () => {
    const f = await fixture(); const digest = totpRetirementRecoverySetDigest(f.codes);
    await f.storage.deleteBackupCodesExpected(f.user.id, digest);
    await f.storage.deleteBackupCodesExpected(f.user.id, digest);
    expect(await f.storage.getBackupCodes(f.user.id)).toBeNull();
  });
  it('rejects a symlinked factor file', async () => {
    const f = await fixture(); const filename = path.join(f.factorDir, 'alice.json');
    await fs.rename(filename, path.join(f.directory, 'elsewhere'));
    await fs.symlink(path.join(f.directory, 'elsewhere'), filename);
    await expect(f.storage.deleteTOTPSecretExpected(f.user.handle, totpRetirementFactorSnapshotDigest(f.factor))).rejects.toThrow();
    expect(await fs.readFile(path.join(f.directory, 'elsewhere'), 'utf8')).toContain(f.factor.encryptedSecret);
  });
  it.each(['factor', 'codes'] as const)('retries directory fsync after an uncertain %s unlink', async target => {
    const f = await fixture();
    const directory = target === 'factor' ? f.factorDir : path.join(f.factorDir, 'backup-codes');
    const open = fs.open.bind(fs); let injected = false;
    vi.spyOn(fs, 'open').mockImplementation(async (...args: Parameters<typeof fs.open>) => {
      const handle = await open(...args);
      if (String(args[0]) === directory && !injected) {
        injected = true; vi.spyOn(handle, 'sync').mockRejectedValueOnce(new Error('directory sync fault'));
      }
      return handle;
    });
    const remove = () => target === 'factor'
      ? f.storage.deleteTOTPSecretExpected(f.user.handle, totpRetirementFactorSnapshotDigest(f.factor))
      : f.storage.deleteBackupCodesExpected(f.user.id, totpRetirementRecoverySetDigest(f.codes));
    await expect(remove()).rejects.toThrow(); expect(injected).toBe(true);
    expect(target === 'factor' ? await f.storage.getTOTPSecret(f.user.handle) : await f.storage.getBackupCodes(f.user.id)).toBeNull();
    await remove(); // Missing target still requires the next successful parent sync.
  });
});
