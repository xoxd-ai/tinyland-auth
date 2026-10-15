import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FileStorageAdapter } from '../src/storage/file.js';
import type { AdminUser, BackupCodeSet, EncryptedTOTPSecret } from '../src/types/auth.js';

const ownedDirectories: string[] = [];
const timestamp = '2026-09-19T12:00:00.000Z';

function userData(handle: string): Omit<AdminUser, 'id'> {
  return {
    handle,
    passwordHash: 'existing-password-hash',
    role: 'member',
    totpEnabled: false,
    isActive: true,
    needsOnboarding: true,
    onboardingStep: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

const factor: EncryptedTOTPSecret = {
  userId: 'alice-id',
  handle: 'alice',
  encryptedSecret: 'encrypted-factor-material',
  iv: 'factor-iv',
  authTag: 'factor-tag',
  salt: 'factor-salt',
  createdAt: timestamp,
  lastUsedAt: timestamp,
  lastUsedTotpStep: 59_660_401,
  backupCodesGenerated: true,
  version: 1,
};

const backupCodes: BackupCodeSet = {
  userId: 'alice-id',
  generatedAt: timestamp,
  lastUsedAt: timestamp,
  codes: Array.from({ length: 10 }, (_, index) => ({
    id: `code-${index}`,
    hash: index.toString(16).repeat(64),
    used: index === 0,
    ...(index === 0 ? { usedAt: timestamp } : {}),
  })),
};

async function fixture() {
  const directory = await fs.mkdtemp(path.join(tmpdir(), 'tinyland-auth-file-durability-'));
  ownedDirectories.push(directory);
  const authDirectory = path.join(directory, 'auth');
  const factorDirectory = path.join(directory, 'totp');
  // FileStorage joins configured paths to cwd; relative paths keep all writes
  // inside this exact mkdtemp root without changing the process-wide cwd.
  const config = {
    authDir: path.relative(process.cwd(), authDirectory),
    totpDir: path.relative(process.cwd(), factorDirectory),
  };
  const adapter = new FileStorageAdapter(config);
  await adapter.init();
  return {
    directory, adapter,
    fresh: () => new FileStorageAdapter(config),
    userFile: path.join(authDirectory, 'admin-users.json'),
    factorFile: path.join(factorDirectory, 'alice.json'),
    backupFile: path.join(factorDirectory, 'backup-codes', 'alice-id.json'),
  };
}

afterEach(async () => {
  vi.restoreAllMocks();
  // Never delete a configured adapter path: remove only our own mkdtemp roots.
  for (const directory of ownedDirectories.splice(0)) {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

describe.each(['factor', 'backup codes'] as const)('FileStorageAdapter fail-closed %s reads', (kind) => {
  async function credentialFixture() {
    const f = await fixture();
    const filename = kind === 'factor' ? f.factorFile : f.backupFile;
    const material = kind === 'factor' ? factor : backupCodes;
    return {
      ...f, filename, material,
      read: () => kind === 'factor' ? f.fresh().getTOTPSecret('alice') : f.fresh().getBackupCodes('alice-id'),
    };
  }

  it('returns null only when the credential file is absent', async () => {
    const f = await credentialFixture();

    await expect(f.read()).resolves.toBeNull();
  });

  it('preserves valid credential metadata and already-consumed backup flags', async () => {
    const f = await credentialFixture();
    if (kind === 'factor') await f.adapter.saveTOTPSecret('alice', factor);
    else await f.adapter.saveBackupCodes('alice-id', backupCodes);
    const before = await fs.readFile(f.filename, 'utf8');

    await expect(f.read()).resolves.toEqual(f.material);

    expect(await fs.readFile(f.filename, 'utf8')).toBe(before);
    if (kind === 'backup codes') {
      const current = await f.fresh().getBackupCodes('alice-id');
      expect(current!.codes[0]).toMatchObject({ used: true, usedAt: timestamp });
      expect(current!.codes[1].used).toBe(false);
    }
  });

  it.each([
    ['invalid JSON', '{'],
    ['JSON null', 'null'],
    ['array', '[]'],
    ['string', '"credential"'],
    ['number', '42'],
    ['empty object', '{}'],
  ])('rejects %s without treating existing data as absent or overwriting it', async (_label, raw) => {
    const f = await credentialFixture();
    await fs.writeFile(f.filename, raw, 'utf8');
    const rename = vi.spyOn(fs, 'rename');

    await expect(f.read()).rejects.toBeDefined();

    expect(await fs.readFile(f.filename, 'utf8')).toBe(raw);
    expect(rename).not.toHaveBeenCalled();
  });

  it.each(['EACCES', 'EIO'])('propagates %s rather than authorizing credential replacement', async (code) => {
    const f = await credentialFixture();
    const raw = JSON.stringify(f.material);
    await fs.writeFile(f.filename, raw, 'utf8');
    const error = Object.assign(new Error(`credential read failed: ${code}`), { code });
    vi.spyOn(fs, 'readFile').mockRejectedValueOnce(error);
    const rename = vi.spyOn(fs, 'rename');

    await expect(f.read()).rejects.toBe(error);

    expect(await fs.readFile(f.filename, 'utf8')).toBe(raw);
    expect(rename).not.toHaveBeenCalled();
  });

  it('rejects a credential stored under the wrong principal binding', async () => {
    const f = await credentialFixture();
    const wrongBinding = kind === 'factor'
      ? { ...factor, handle: 'someone-else' }
      : { ...backupCodes, userId: 'someone-else-id' };
    const raw = JSON.stringify(wrongBinding);
    await fs.writeFile(f.filename, raw, 'utf8');

    await expect(f.read()).rejects.toBeDefined();

    expect(await fs.readFile(f.filename, 'utf8')).toBe(raw);
  });

  it.each(['missing required field', 'malformed timestamp'])('rejects a record with %s', async (damage) => {
    const f = await credentialFixture();
    const record = JSON.parse(JSON.stringify(f.material)) as Record<string, unknown>;
    if (damage === 'missing required field') delete record[kind === 'factor' ? 'encryptedSecret' : 'codes'];
    else record[kind === 'factor' ? 'createdAt' : 'generatedAt'] = 'not-a-timestamp';
    const raw = JSON.stringify(record);
    await fs.writeFile(f.filename, raw, 'utf8');

    await expect(f.read()).rejects.toBeDefined();

    expect(await fs.readFile(f.filename, 'utf8')).toBe(raw);
  });
});

describe('FileStorageAdapter backup-code record validation', () => {
  it.each([
    ['invalid code hash', { hash: 'not-a-sha256-hash' }],
    ['non-boolean used state', { used: 'false' }],
    ['malformed used timestamp', { usedAt: 'not-a-timestamp' }],
  ] as const)('rejects %s without resetting recovery codes', async (_label, patch) => {
    const f = await fixture();
    const raw = JSON.stringify({
      ...backupCodes,
      codes: backupCodes.codes.map((code, index) => index === 0 ? { ...code, ...patch } : code),
    });
    await fs.writeFile(f.backupFile, raw, 'utf8');

    await expect(f.fresh().getBackupCodes('alice-id')).rejects.toBeDefined();

    expect(await fs.readFile(f.backupFile, 'utf8')).toBe(raw);
  });
});

describe('FileStorageAdapter durable private writes', () => {
  it('creates a 0600 user file readable by a fresh adapter', async () => {
    const f = await fixture();

    const user = await f.adapter.createUser(userData('alice'));

    expect((await fs.stat(f.userFile)).mode & 0o777).toBe(0o600);
    expect(await f.fresh().getUser(user.id)).toEqual(user);
    expect(JSON.parse(await fs.readFile(f.userFile, 'utf8'))).toEqual([user]);
  });

  it('writes and replaces a 0600 factor file readable by a fresh adapter', async () => {
    const f = await fixture();
    await f.adapter.saveTOTPSecret('alice', factor);
    expect((await fs.stat(f.factorFile)).mode & 0o777).toBe(0o600);
    expect(await f.fresh().getTOTPSecret('alice')).toEqual(factor);
    const replacement = { ...factor, encryptedSecret: 'replacement-encrypted-material' };

    await f.adapter.saveTOTPSecret('alice', replacement);

    expect((await fs.stat(f.factorFile)).mode & 0o777).toBe(0o600);
    expect(await f.fresh().getTOTPSecret('alice')).toEqual(replacement);
    expect(JSON.parse(await fs.readFile(f.factorFile, 'utf8'))).toEqual(replacement);
  });

  it.each(['factor', 'user'] as const)('preserves the prior %s record when temporary-file sync fails before rename', async (kind) => {
    const f = await fixture();
    const firstUser = await f.adapter.createUser(userData('alice'));
    await f.adapter.saveTOTPSecret('alice', factor);
    const filename = kind === 'factor' ? f.factorFile : f.userFile;
    const before = await fs.readFile(filename, 'utf8');
    const nativeOpen = fs.open.bind(fs);
    vi.spyOn(fs, 'open').mockImplementation(async (file, flags, mode) => {
      const handle = await nativeOpen(file, flags, mode);
      if (typeof file === 'string' && file.startsWith(`${filename}.`) && file.endsWith('.tmp')) {
        vi.spyOn(handle, 'sync').mockRejectedValueOnce(new Error('temporary file fsync unavailable'));
      }
      return handle;
    });
    const rename = vi.spyOn(fs, 'rename');

    const write = kind === 'factor'
      ? f.adapter.saveTOTPSecret('alice', { ...factor, encryptedSecret: 'new-material' })
      : f.adapter.createUser(userData('bob'));
    await expect(write).rejects.toThrow('temporary file fsync unavailable');

    expect(rename).not.toHaveBeenCalled();
    expect(await fs.readFile(filename, 'utf8')).toBe(before);
    expect(await f.fresh().getTOTPSecret('alice')).toEqual(factor);
    expect(await f.fresh().getUser(firstUser.id)).toEqual(firstUser);
    expect(await f.fresh().getUserByHandle('bob')).toBeNull();
    expect((await fs.readdir(path.dirname(filename))).some((entry) => entry.endsWith('.tmp'))).toBe(false);
  });

  it.each(['factor', 'user'] as const)('rejects a %s write when renamed data cannot receive a directory-sync acknowledgment', async (kind) => {
    const f = await fixture();
    const filename = kind === 'factor' ? f.factorFile : f.userFile;
    const nativeOpen = fs.open.bind(fs);
    vi.spyOn(fs, 'open').mockImplementation(async (file, flags, mode) => {
      const handle = await nativeOpen(file, flags, mode);
      if (file === path.dirname(filename) && flags === 'r') {
        vi.spyOn(handle, 'sync').mockRejectedValueOnce(new Error('directory fsync unavailable'));
      }
      return handle;
    });

    const write = kind === 'factor'
      ? f.adapter.saveTOTPSecret('alice', factor)
      : f.adapter.createUser(userData('alice'));
    await expect(write).rejects.toThrow('directory fsync unavailable');

    // Rename already happened: visibility is not a durable-success receipt.
    // The caller/coordinator must keep its recovery gate closed on rejection.
    expect((await fs.stat(filename)).mode & 0o777).toBe(0o600);
    if (kind === 'factor') expect(await f.fresh().getTOTPSecret('alice')).toEqual(factor);
    else expect(await f.fresh().getUserByHandle('alice')).toMatchObject({
      ...userData('alice'), createdAt: expect.any(String), updatedAt: expect.any(String),
    });
    expect((await fs.readdir(path.dirname(filename))).some((entry) => entry.endsWith('.tmp'))).toBe(false);
  });
});
