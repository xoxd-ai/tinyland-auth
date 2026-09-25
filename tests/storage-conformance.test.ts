import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { FileStorageAdapter } from '../src/storage/file.js';
import { MemoryStorageAdapter } from '../src/storage/memory.js';
import {
  runFirstUserBootstrapStorageConformance,
  type FirstUserBootstrapConformanceHarness,
} from '../src/storage/conformance.js';
import {
  createFirstUserBootstrapReceipt,
  type InertFirstUserClaim,
} from '../src/storage/firstUserBootstrap.js';
import type { IStorageAdapter } from '../src/storage/interface.js';
import type { AdminUser } from '../src/types/auth.js';
import {
  describeStorageConformance,
  makeClaim,
  makeFinalization,
} from './storage-conformance.js';

const TENANT = '12345678-1234-4123-8123-123456789abc';
const CONFORMANCE_CLOCK_ORIGIN_MS = Date.parse('2040-01-02T03:04:05.000Z');
const LEGACY_FILE_FIXTURE = fileURLToPath(
  new URL('./fixtures/legacy-0.7-file-store', import.meta.url),
);

const FILE_SESSION_MUTATIONS: Array<{
  name: string;
  expireTarget?: boolean;
  run: (
    storage: FileStorageAdapter,
    targetSessionId: string,
    targetUserId: string,
  ) => Promise<unknown>;
}> = [
  {
    name: 'deleteSession',
    run: (storage, targetSessionId) => storage.deleteSession(targetSessionId),
  },
  {
    name: 'deleteUserSessions',
    run: (storage, _targetSessionId, targetUserId) =>
      storage.deleteUserSessions(targetUserId),
  },
  {
    name: 'cleanupExpiredSessions',
    expireTarget: true,
    run: (storage) => storage.cleanupExpiredSessions(),
  },
];

function makeLegacyInvitee(handle: string): Omit<AdminUser, 'id'> {
  const timestamp = new Date().toISOString();
  return {
    handle,
    passwordHash: `$2b$12$${'C'.repeat(53)}`,
    totpEnabled: false,
    role: 'member',
    isActive: true,
    needsOnboarding: false,
    onboardingStep: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

async function copyLegacyFileFixture(label: string): Promise<{
  root: string;
  authDir: string;
  totpDir: string;
}> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), label));
  const storeRoot = path.join(root, 'store');
  await fs.cp(LEGACY_FILE_FIXTURE, storeRoot, { recursive: true });
  await fs.chmod(path.join(storeRoot, 'auth', 'admin-users.json'), 0o600);
  return {
    root,
    authDir: path.join(storeRoot, 'auth'),
    totpDir: path.join(storeRoot, 'totp'),
  };
}

function clockControlledHarness(
  storage: IStorageAdapter,
  cleanup: () => Promise<void> = async () => undefined,
): FirstUserBootstrapConformanceHarness {
  let nowMs = CONFORMANCE_CLOCK_ORIGIN_MS;
  vi.setSystemTime(nowMs);
  return {
    storage,
    now: () => new Date(nowMs),
    advanceTime: async (ms) => {
      nowMs += ms;
      vi.setSystemTime(nowMs);
    },
    cleanup,
  };
}

function overrideBootstrapBoundary(
  storage: IStorageAdapter,
  overrides: Partial<Pick<
    IStorageAdapter,
    | 'claimFirstUserBootstrap'
    | 'finalizeFirstUserBootstrap'
    | 'getFirstUserBootstrapReceipt'
    | 'createUser'
  >>,
): IStorageAdapter {
  return new Proxy(storage, {
    get(target, property, receiver) {
      const override = overrides[property as keyof typeof overrides];
      if (override) return override;
      const value = Reflect.get(target, property, receiver) as unknown;
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

async function expectSingleReleasedLockSlot(lockDir: string): Promise<void> {
  const entries = (await fs.readdir(lockDir)).sort();
  expect(entries).toHaveLength(4);
  const owner = entries.find((entry) => entry.endsWith('.owner'));
  const held = entries.find((entry) => entry.endsWith('.held'));
  const releasing = entries.find((entry) => entry.endsWith('.releasing'));
  const released = entries.find((entry) => entry.endsWith('.released'));
  expect(owner).toBeDefined();
  expect(held).toBeDefined();
  expect(releasing).toBeDefined();
  expect(released).toBeDefined();
  expect(owner?.split('.')[0]).toBe(held?.split('.')[0]);
  expect(owner?.split('.')[0]).toBe(releasing?.split('.')[0]);
  expect(owner?.split('.')[0]).toBe(released?.split('.')[0]);
  const [ownerStat, heldStat, releasingStat, releaseStat] = await Promise.all([
    fs.stat(path.join(lockDir, owner!)),
    fs.stat(path.join(lockDir, held!)),
    fs.stat(path.join(lockDir, releasing!)),
    fs.stat(path.join(lockDir, released!)),
  ]);
  for (const stat of [heldStat, releasingStat, releaseStat]) {
    expect({ dev: ownerStat.dev, ino: ownerStat.ino }).toEqual({
      dev: stat.dev,
      ino: stat.ino,
    });
  }
}

describeStorageConformance('MemoryStorageAdapter', async (_tenantId) => ({
  storage: new MemoryStorageAdapter(),
  cleanup: async () => undefined,
}));

describeStorageConformance('FileStorageAdapter', async (_tenantId) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-storage-'));
  return {
    storage: new FileStorageAdapter({
      authDir: path.join(root, 'auth'),
      totpDir: path.join(root, 'totp'),
    }),
    cleanup: async () => fs.rm(root, { recursive: true, force: true }),
  };
});

describe('FileStorageAdapter first-user bootstrap custody', () => {
  it('acquires and releases the filesystem lock for claim and finalization', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-lock-lifecycle-'));
    const totpDir = path.join(root, 'totp');
    const storage = new FileStorageAdapter({
      authDir: path.join(root, 'auth'),
      totpDir,
      firstUserBootstrapLockTimeoutMs: 100,
      firstUserBootstrapLockRetryMs: 5,
    });
    await storage.init();
    const lockDir = path.join(totpDir, '.first-user-bootstrap.lock');
    const claim = makeClaim();
    const finalization = makeFinalization(claim);

    try {
      await expect(storage.claimFirstUserBootstrap(claim)).resolves.toEqual(claim);
      await expectSingleReleasedLockSlot(lockDir);

      await expect(storage.finalizeFirstUserBootstrap(finalization)).resolves.toMatchObject({
        tenantId: TENANT,
        attemptId: claim.attemptId,
      });
      await expectSingleReleasedLockSlot(lockDir);
      await expect(storage.getFirstUserBootstrapReceipt(TENANT)).resolves.toMatchObject({
        tenantId: TENANT,
        attemptId: claim.attemptId,
      });
      for (let index = 0; index < 20; index += 1) {
        await storage.updateUser(claim.actor.id, {
          displayName: `Synthetic Admin ${index}`,
        });
      }
      await expectSingleReleasedLockSlot(lockDir);
    } finally {
      await storage.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it.each(FILE_SESSION_MUTATIONS)(
    'serializes $name with bootstrap session revocation',
    async ({ name, expireTarget, run }) => {
      const root = await fs.mkdtemp(path.join(os.tmpdir(), `tinyland-auth-${name}-race-`));
      const config = {
        authDir: path.join(root, 'auth'),
        totpDir: path.join(root, 'totp'),
        firstUserBootstrapLockTimeoutMs: 2000,
        firstUserBootstrapLockRetryMs: 1,
      };
      const mutator = new FileStorageAdapter(config);
      const claimer = new FileStorageAdapter(config);
      const verifier = new FileStorageAdapter(config);
      await Promise.all([mutator.init(), claimer.init(), verifier.init()]);

      type SessionRaceInternals = {
        readJsonFile<T>(filePath: string, defaultValue: T): Promise<T>;
        waitForFirstUserBootstrapLock(deadline: number): Promise<void>;
      };
      const mutatorInternals = mutator as unknown as SessionRaceInternals;
      const claimerInternals = claimer as unknown as SessionRaceInternals;
      const originalRead = mutatorInternals.readJsonFile.bind(mutatorInternals);
      const originalWait = claimerInternals.waitForFirstUserBootstrapLock.bind(claimerInternals);
      const sessionsPath = path.resolve(config.authDir, 'sessions.json');
      let signalSnapshotRead!: () => void;
      const snapshotRead = new Promise<void>((resolve) => { signalSnapshotRead = resolve; });
      let releaseSnapshot!: () => void;
      const snapshotGate = new Promise<void>((resolve) => { releaseSnapshot = resolve; });
      let signalClaimWait!: () => void;
      const claimWait = new Promise<void>((resolve) => { signalClaimWait = resolve; });
      let staleSessionCount = -1;
      let armed = false;
      let paused = false;
      mutatorInternals.readJsonFile = async <T>(
        filePath: string,
        defaultValue: T,
      ): Promise<T> => {
        const value = await originalRead(filePath, defaultValue);
        if (armed && !paused && path.resolve(filePath) === sessionsPath) {
          paused = true;
          staleSessionCount = Array.isArray(value) ? value.length : -1;
          signalSnapshotRead();
          await snapshotGate;
        }
        return value;
      };
      claimerInternals.waitForFirstUserBootstrapLock = async (deadline) => {
        signalClaimWait();
        await originalWait(deadline);
      };

      let mutationPromise: Promise<unknown> | undefined;
      let claimPromise: Promise<InertFirstUserClaim> | undefined;
      try {
        const targetUserId = `pre-claim-target-${name}`;
        const survivorUserId = `pre-claim-survivor-${name}`;
        const target = await mutator.createSession(targetUserId, {
          id: targetUserId,
          handle: 'pre_claim_target',
          role: 'super_admin',
        });
        await mutator.createSession(survivorUserId, {
          id: survivorUserId,
          handle: 'pre_claim_survivor',
          role: 'super_admin',
        });
        if (expireTarget) {
          await mutator.updateSession(target.id, {
            expires: '2000-01-01T00:00:00.000Z',
          });
        }

        armed = true;
        mutationPromise = run(mutator, target.id, targetUserId);
        await snapshotRead;
        expect(staleSessionCount).toBe(2);

        claimPromise = claimer.claimFirstUserBootstrap(makeClaim());
        const claimOrder = await Promise.race([
          claimPromise.then(() => 'completed-before-mutation' as const),
          claimWait.then(() => 'blocked-by-mutation' as const),
        ]);
        releaseSnapshot();
        await Promise.all([mutationPromise, claimPromise]);

        expect(await verifier.getFirstUserBootstrapReceipt(TENANT)).toBeNull();
        expect(await verifier.getAllSessions()).toEqual([]);
        expect(claimOrder).toBe('blocked-by-mutation');
      } finally {
        releaseSnapshot();
        await Promise.allSettled([
          ...(mutationPromise ? [mutationPromise] : []),
          ...(claimPromise ? [claimPromise] : []),
        ]);
        mutatorInternals.readJsonFile = originalRead;
        claimerInternals.waitForFirstUserBootstrapLock = originalWait;
        await Promise.all([mutator.close(), claimer.close(), verifier.close()]);
        await fs.rm(root, { recursive: true, force: true });
      }
    },
  );

  it('keeps bootstrap state under totpDir and fails closed on corruption', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-custody-'));
    const authDir = path.join(root, 'auth');
    const totpDir = path.join(root, 'totp');
    const storage = new FileStorageAdapter({ authDir, totpDir });
    await storage.init();

    try {
      const bootstrapPath = storage.getFirstUserBootstrapPath(TENANT);
      expect(path.resolve(bootstrapPath).startsWith(path.resolve(totpDir))).toBe(true);
      expect(path.resolve(bootstrapPath).startsWith(path.resolve(authDir))).toBe(false);

      await fs.writeFile(bootstrapPath, '{corrupted-json', 'utf8');
      await expect(storage.getFirstUserBootstrapReceipt(TENANT)).rejects.toThrow();

      await fs.writeFile(bootstrapPath, 'null', 'utf8');
      await expect(storage.getFirstUserBootstrapReceipt(TENANT)).rejects.toThrow(
        /corrupted first-user bootstrap record/i,
      );
      await expect(storage.claimFirstUserBootstrap(makeClaim())).rejects.toThrow(
        /corrupted first-user bootstrap record/i,
      );
      await expect(storage.hasUsers()).rejects.toThrow(
        /corrupted first-user bootstrap record/i,
      );
    } finally {
      await storage.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('reopens finalized state durably and rejects a corrupted receipt', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-reopen-'));
    const config = {
      authDir: path.join(root, 'auth'),
      totpDir: path.join(root, 'totp'),
    };
    const claim = makeClaim();
    const finalization = makeFinalization(claim);
    const first = new FileStorageAdapter(config);
    await first.init();

    try {
      await first.claimFirstUserBootstrap(claim);
      const receipt = await first.finalizeFirstUserBootstrap(finalization);
      await first.close();

      const reopened = new FileStorageAdapter(config);
      await reopened.init();
      expect(await reopened.getFirstUserBootstrapReceipt(TENANT)).toEqual(receipt);
      expect(await reopened.getUser(claim.actor.id)).toEqual(finalization.user);
      const concurrent = await Promise.all([
        reopened.finalizeFirstUserBootstrap(finalization),
        reopened.finalizeFirstUserBootstrap(finalization),
      ]);
      expect(concurrent).toEqual([receipt, receipt]);
      await reopened.close();

      const bootstrapPath = first.getFirstUserBootstrapPath(TENANT);
      const record = JSON.parse(await fs.readFile(bootstrapPath, 'utf8')) as {
        receipt: { materialDigest: string };
      };
      record.receipt.materialDigest = '0'.repeat(64);
      await fs.writeFile(bootstrapPath, JSON.stringify(record), 'utf8');

      const corrupted = new FileStorageAdapter(config);
      await corrupted.init();
      await expect(corrupted.getFirstUserBootstrapReceipt(TENANT)).rejects.toThrow(
        /corrupted immutable/i,
      );
      await corrupted.close();
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('rejects optional undefined fields without writing authority', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-undefined-'));
    const config = {
      authDir: path.join(root, 'auth'),
      totpDir: path.join(root, 'totp'),
    };
    const claim = makeClaim();
    const finalization = makeFinalization(claim);
    (finalization.user as { email?: string }).email = undefined;
    const first = new FileStorageAdapter(config);
    await first.init();

    try {
      await first.claimFirstUserBootstrap(claim);
      await expect(first.finalizeFirstUserBootstrap(finalization)).rejects.toThrow();
      expect(await first.getUser(claim.actor.id)).toBeNull();
      expect(await first.getTOTPSecret(claim.actor.handle)).toBeNull();
      expect(await first.getBackupCodes(claim.actor.id)).toBeNull();
      expect(await first.getFirstUserBootstrapReceipt(TENANT)).toBeNull();
      delete finalization.user.email;
      await expect(first.finalizeFirstUserBootstrap(finalization)).resolves.toMatchObject({
        tenantId: TENANT,
      });
      await first.close();
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('fails closed on stale same-PID and dead-PID locks without replacing owners', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-stale-lock-'));
    const totpDir = path.join(root, 'totp');
    const storage = new FileStorageAdapter({
      authDir: path.join(root, 'auth'),
      totpDir,
      firstUserBootstrapLockTimeoutMs: 30,
      firstUserBootstrapLockRetryMs: 5,
    });
    await storage.init();

    try {
      const lockDir = path.join(totpDir, '.first-user-bootstrap.lock');
      const ownerPath = path.join(lockDir, '0.owner');
      await fs.mkdir(lockDir, { recursive: true });
      for (const pid of [process.pid, 999999]) {
        const original = JSON.stringify({
          version: 1,
          pid,
          token: `abandoned-owner-${pid}`,
          createdAt: new Date(Date.now() - 60_000).toISOString(),
        });
        await fs.writeFile(ownerPath, original, 'utf8');
        await expect(storage.claimFirstUserBootstrap(makeClaim())).rejects.toThrow(
          /timed out acquiring/i,
        );
        expect(await fs.readFile(ownerPath, 'utf8')).toBe(original);
      }
    } finally {
      await storage.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('clamps lock retry waits to the remaining acquisition timeout', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-lock-timeout-'));
    const totpDir = path.join(root, 'totp');
    const storage = new FileStorageAdapter({
      authDir: path.join(root, 'auth'),
      totpDir,
      firstUserBootstrapLockTimeoutMs: 30,
      firstUserBootstrapLockRetryMs: 1000,
    });
    await storage.init();
    const lockDir = path.join(totpDir, '.first-user-bootstrap.lock');
    await fs.mkdir(lockDir, { recursive: true });
    await fs.writeFile(path.join(lockDir, '0.owner'), 'active-owner', 'utf8');

    try {
      const startedAt = Date.now();
      await expect(storage.claimFirstUserBootstrap(makeClaim())).rejects.toThrow(
        /timed out acquiring/i,
      );
      expect(Date.now() - startedAt).toBeLessThan(500);
    } finally {
      await storage.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('releases an acquired owner when directory sync fails during acquisition', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-lock-sync-fault-'));
    const totpDir = path.join(root, 'totp');
    const storage = new FileStorageAdapter({
      authDir: path.join(root, 'auth'),
      totpDir,
    });
    await storage.init();
    const lockDir = path.join(totpDir, '.first-user-bootstrap.lock');
    const internals = storage as unknown as {
      syncDirectory(directoryPath: string): Promise<void>;
    };
    const syncSpy = vi.spyOn(internals, 'syncDirectory');
    syncSpy.mockRejectedValueOnce(new Error('injected directory sync failure'));

    try {
      await expect(storage.claimFirstUserBootstrap(makeClaim())).rejects.toThrow(
        /injected directory sync failure/i,
      );
      await expectSingleReleasedLockSlot(lockDir);
      syncSpy.mockRestore();
      await expect(storage.claimFirstUserBootstrap(makeClaim())).resolves.toMatchObject({
        tenantId: TENANT,
      });
      await expectSingleReleasedLockSlot(lockDir);
    } finally {
      syncSpy.mockRestore();
      await storage.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('releases an acquired owner when inode verification fails during acquisition', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-lock-inode-fault-'));
    const totpDir = path.join(root, 'totp');
    const storage = new FileStorageAdapter({
      authDir: path.join(root, 'auth'),
      totpDir,
    });
    await storage.init();
    const lockDir = path.join(totpDir, '.first-user-bootstrap.lock');
    const internals = storage as unknown as {
      assertFirstUserBootstrapLockInode(
        filePath: string,
        ownedStat: { dev: number; ino: number },
      ): Promise<void>;
    };
    const inodeSpy = vi.spyOn(internals, 'assertFirstUserBootstrapLockInode');
    inodeSpy.mockRejectedValueOnce(new Error('injected inode verification failure'));

    try {
      await expect(storage.claimFirstUserBootstrap(makeClaim())).rejects.toThrow(
        /injected inode verification failure/i,
      );
      await expectSingleReleasedLockSlot(lockDir);
      inodeSpy.mockRestore();
      await expect(storage.claimFirstUserBootstrap(makeClaim())).resolves.toMatchObject({
        tenantId: TENANT,
      });
      await expectSingleReleasedLockSlot(lockDir);
    } finally {
      inodeSpy.mockRestore();
      await storage.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('leaves a replacement owner linked when both owner-handle stat attempts fail', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-lock-stat-fault-'));
    const totpDir = path.join(root, 'totp');
    const storage = new FileStorageAdapter({
      authDir: path.join(root, 'auth'),
      totpDir,
      firstUserBootstrapLockTimeoutMs: 30,
      firstUserBootstrapLockRetryMs: 5,
    });
    await storage.init();
    const lockDir = path.join(totpDir, '.first-user-bootstrap.lock');
    const ownerPath = path.join(lockDir, '0.owner');
    const originalOpen = fs.open.bind(fs);
    const originalUnlink = fs.unlink.bind(fs);
    let statAttempts = 0;
    let replacementStat: Awaited<ReturnType<typeof fs.stat>> | undefined;
    const openSpy = vi.spyOn(fs, 'open').mockImplementation(async (
      filePath,
      flags,
      mode,
    ) => {
      const handle = await originalOpen(filePath, flags, mode);
      if (path.resolve(String(filePath)) === path.resolve(ownerPath) && flags === 'wx') {
        vi.spyOn(handle, 'stat').mockImplementation(async () => {
          statAttempts += 1;
          if (statAttempts === 2) {
            await originalUnlink(ownerPath);
            const replacement = await originalOpen(ownerPath, 'wx', 0o600);
            try {
              await replacement.writeFile('replacement-owner', 'utf8');
              await replacement.sync();
              replacementStat = await replacement.stat();
            } finally {
              await replacement.close();
            }
          }
          throw new Error(`injected owner-handle stat failure ${statAttempts}`);
        });
      }
      return handle;
    });
    const linkSpy = vi.spyOn(fs, 'link');
    const unlinkSpy = vi.spyOn(fs, 'unlink');

    try {
      await expect(storage.claimFirstUserBootstrap(makeClaim())).rejects.toThrow(
        /cannot authenticate.*owner path was left untouched/i,
      );
      expect(statAttempts).toBe(2);
      expect(linkSpy).not.toHaveBeenCalled();
      expect(unlinkSpy).not.toHaveBeenCalled();
      expect(await fs.readdir(lockDir)).toEqual(['0.owner']);
      expect(await fs.readFile(ownerPath, 'utf8')).toBe('replacement-owner');
      const linkedStat = await fs.stat(ownerPath);
      expect({ dev: linkedStat.dev, ino: linkedStat.ino }).toEqual({
        dev: replacementStat?.dev,
        ino: replacementStat?.ino,
      });

      openSpy.mockRestore();
      linkSpy.mockRestore();
      unlinkSpy.mockRestore();
      await expect(storage.claimFirstUserBootstrap(makeClaim())).rejects.toThrow(
        /timed out acquiring/i,
      );
      expect(await fs.readFile(ownerPath, 'utf8')).toBe('replacement-owner');
      expect((await fs.stat(ownerPath)).ino).toBe(replacementStat?.ino);
    } finally {
      openSpy.mockRestore();
      linkSpy.mockRestore();
      unlinkSpy.mockRestore();
      await storage.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('retries a torn releasing-to-released observation and then resolves', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-lock-observation-'));
    const totpDir = path.join(root, 'totp');
    const storage = new FileStorageAdapter({
      authDir: path.join(root, 'auth'),
      totpDir,
    });
    await storage.init();
    const lockDir = path.join(totpDir, '.first-user-bootstrap.lock');
    const ownerPath = path.join(lockDir, '0.owner');
    const heldPath = path.join(lockDir, '0.held');
    const releasingPath = path.join(lockDir, '0.releasing');
    const releasedPath = path.join(lockDir, '0.released');
    await fs.mkdir(lockDir, { recursive: true });
    await fs.writeFile(ownerPath, 'released-owner', { flag: 'wx', mode: 0o600 });
    await fs.link(ownerPath, heldPath);
    const internals = storage as unknown as {
      inspectFirstUserBootstrapLock(lockDirPath: string): Promise<{ kind: string }>;
      lstatFirstUserBootstrapLockPath(
        filePath: string,
      ): Promise<Awaited<ReturnType<typeof fs.lstat>> | null>;
    };
    const originalLstat = internals.lstatFirstUserBootstrapLockPath.bind(internals);
    let publicationComplete = false;
    let signalPublication!: () => void;
    const publication = new Promise<void>((resolve) => {
      signalPublication = resolve;
    });
    const lstatSpy = vi.spyOn(internals, 'lstatFirstUserBootstrapLockPath')
      .mockImplementation(async (filePath) => {
        if (filePath === releasingPath && !publicationComplete) {
          const observed = await originalLstat(filePath);
          await fs.link(ownerPath, releasingPath);
          await fs.link(releasingPath, releasedPath);
          publicationComplete = true;
          signalPublication();
          return observed;
        }
        if (filePath === releasedPath && !publicationComplete) {
          await publication;
        }
        return originalLstat(filePath);
      });

    try {
      await expect(internals.inspectFirstUserBootstrapLock(lockDir)).resolves.toEqual({
        kind: 'retry',
      });
      await expect(storage.claimFirstUserBootstrap(makeClaim())).resolves.toMatchObject({
        tenantId: TENANT,
      });
      await expectSingleReleasedLockSlot(lockDir);
    } finally {
      signalPublication();
      lstatSpy.mockRestore();
      await storage.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('fails closed for stable dual-slot owner occupancy', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-lock-dual-owner-'));
    const totpDir = path.join(root, 'totp');
    const storage = new FileStorageAdapter({
      authDir: path.join(root, 'auth'),
      totpDir,
    });
    await storage.init();
    const lockDir = path.join(totpDir, '.first-user-bootstrap.lock');
    await fs.mkdir(lockDir, { recursive: true });
    const ownerStats: Array<{ path: string; dev: number; ino: number }> = [];
    for (const slot of [0, 1]) {
      const ownerPath = path.join(lockDir, `${slot}.owner`);
      const heldPath = path.join(lockDir, `${slot}.held`);
      await fs.writeFile(ownerPath, `owner-${slot}`, { flag: 'wx', mode: 0o600 });
      await fs.link(ownerPath, heldPath);
      const stat = await fs.stat(ownerPath);
      ownerStats.push({ path: ownerPath, dev: stat.dev, ino: stat.ino });
    }

    try {
      await expect(storage.claimFirstUserBootstrap(makeClaim())).rejects.toThrow(
        /lock slots are ambiguous/i,
      );
      for (const owner of ownerStats) {
        const stat = await fs.stat(owner.path);
        expect({ dev: stat.dev, ino: stat.ino }).toEqual({
          dev: owner.dev,
          ino: owner.ino,
        });
      }
    } finally {
      await storage.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('serializes three simultaneous claims across separate adapter instances', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-three-adapters-'));
    const config = {
      authDir: path.join(root, 'auth'),
      totpDir: path.join(root, 'totp'),
    };
    const first = new FileStorageAdapter(config);
    const second = new FileStorageAdapter(config);
    const third = new FileStorageAdapter(config);
    await Promise.all([first.init(), second.init(), third.init()]);
    const firstClaim = makeClaim();
    const secondClaim = makeClaim({
      attemptId: 'synthetic-attempt-2',
      actor: {
        ...firstClaim.actor,
        id: 'synthetic-user-2',
        handle: 'bootstrap_second',
      },
    });
    const thirdClaim = makeClaim({
      attemptId: 'synthetic-attempt-3',
      actor: {
        ...firstClaim.actor,
        id: 'synthetic-user-3',
        handle: 'bootstrap_third',
      },
    });
    const bootstrapPath = first.getFirstUserBootstrapPath(TENANT);
    const originalRename = fs.rename.bind(fs);
    type LockWaiter = {
      waitForFirstUserBootstrapLock(deadline: number): Promise<void>;
    };
    const secondInternals = second as unknown as LockWaiter;
    const thirdInternals = third as unknown as LockWaiter;
    const secondWait = secondInternals.waitForFirstUserBootstrapLock.bind(secondInternals);
    const thirdWait = thirdInternals.waitForFirstUserBootstrapLock.bind(thirdInternals);
    let secondBlocked!: () => void;
    let thirdBlocked!: () => void;
    const secondAtWait = new Promise<void>((resolve) => { secondBlocked = resolve; });
    const thirdAtWait = new Promise<void>((resolve) => { thirdBlocked = resolve; });
    const secondWaitSpy = vi.spyOn(secondInternals, 'waitForFirstUserBootstrapLock')
      .mockImplementation(async (deadline) => {
        secondBlocked();
        await secondWait(deadline);
      });
    const thirdWaitSpy = vi.spyOn(thirdInternals, 'waitForFirstUserBootstrapLock')
      .mockImplementation(async (deadline) => {
        thirdBlocked();
        await thirdWait(deadline);
      });
    let holderReachedWrite!: () => void;
    const holderAtWrite = new Promise<void>((resolve) => {
      holderReachedWrite = resolve;
    });
    let releaseHolder!: () => void;
    const holderGate = new Promise<void>((resolve) => {
      releaseHolder = resolve;
    });
    const renameSpy = vi.spyOn(fs, 'rename').mockImplementation(async (from, to) => {
      if (path.resolve(String(to)) === path.resolve(bootstrapPath)) {
        holderReachedWrite();
        await holderGate;
      }
      await originalRename(from, to);
    });

    try {
      const holder = first.claimFirstUserBootstrap(firstClaim);
      await holderAtWrite;
      const resultsPromise = Promise.allSettled([
        holder,
        second.claimFirstUserBootstrap(secondClaim),
        third.claimFirstUserBootstrap(thirdClaim),
      ]);
      await Promise.all([secondAtWait, thirdAtWait]);
      releaseHolder();
      const results = await resultsPromise;
      expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      expect(results.filter((result) => result.status === 'rejected')).toHaveLength(2);
    } finally {
      releaseHolder();
      renameSpy.mockRestore();
      secondWaitSpy.mockRestore();
      thirdWaitSpy.mockRestore();
      await Promise.all([first.close(), second.close(), third.close()]);
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('lets the next owner compact only after final release publication', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-release-publish-'));
    const config = {
      authDir: path.join(root, 'auth'),
      totpDir: path.join(root, 'totp'),
    };
    const first = new FileStorageAdapter(config);
    const second = new FileStorageAdapter(config);
    await Promise.all([first.init(), second.init()]);
    const originalLink = fs.link.bind(fs);
    let releasePublished!: () => void;
    const published = new Promise<void>((resolve) => {
      releasePublished = resolve;
    });
    let letFirstReturn!: () => void;
    const returnGate = new Promise<void>((resolve) => {
      letFirstReturn = resolve;
    });
    let paused = false;
    const linkSpy = vi.spyOn(fs, 'link').mockImplementation(async (existingPath, newPath) => {
      await originalLink(existingPath, newPath);
      if (!paused && String(newPath).endsWith('.released')) {
        paused = true;
        releasePublished();
        await returnGate;
      }
    });

    try {
      const claim = makeClaim();
      const firstClaim = first.claimFirstUserBootstrap(claim);
      await published;
      await expect(second.claimFirstUserBootstrap(makeClaim({
        attemptId: 'synthetic-published-contender',
      }))).rejects.toThrow(/different first-user bootstrap claim/i);
      letFirstReturn();
      await expect(firstClaim).resolves.toEqual(claim);
      await expectSingleReleasedLockSlot(
        path.join(config.totpDir, '.first-user-bootstrap.lock'),
      );
    } finally {
      letFirstReturn();
      linkSpy.mockRestore();
      await Promise.all([first.close(), second.close()]);
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('preserves a replacement owner introduced after the release ownership check', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-lock-replaced-'));
    const totpDir = path.join(root, 'totp');
    const storage = new FileStorageAdapter({
      authDir: path.join(root, 'auth'),
      totpDir,
    });
    await storage.init();
    const originalLink = fs.link.bind(fs);
    const originalUnlink = fs.unlink.bind(fs);
    let replacementPath = '';
    let replacementStat: Awaited<ReturnType<typeof fs.stat>> | undefined;
    const linkSpy = vi.spyOn(fs, 'link').mockImplementation(async (existingPath, newPath) => {
      if (String(newPath).endsWith('.releasing') && replacementPath.length === 0) {
        replacementPath = String(newPath).replace(/\.releasing$/, '.owner');
        await originalUnlink(replacementPath);
        await fs.writeFile(replacementPath, 'replacement-owner', {
          flag: 'wx',
          mode: 0o600,
        });
        replacementStat = await fs.stat(replacementPath);
      }
      await originalLink(existingPath, newPath);
    });

    try {
      await expect(storage.claimFirstUserBootstrap(makeClaim())).rejects.toThrow(
        /ownership changed/i,
      );
      expect(replacementPath.endsWith('.owner')).toBe(true);
      expect(await fs.readFile(replacementPath, 'utf8')).toBe('replacement-owner');
      expect((await fs.stat(replacementPath)).ino).toBe(replacementStat?.ino);
      await expect(storage.claimFirstUserBootstrap(makeClaim())).rejects.toThrow(
        /ownership is ambiguous/i,
      );
    } finally {
      linkSpy.mockRestore();
      await storage.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('binds canonical tenant contents to the expected tenant filename', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-tenant-bind-'));
    const storage = new FileStorageAdapter({
      authDir: path.join(root, 'auth'),
      totpDir: path.join(root, 'totp'),
    });
    await storage.init();
    const otherTenant = '87654321-4321-4321-8321-cba987654321';

    try {
      const uppercaseClaim = makeClaim({ tenantId: TENANT.toUpperCase() });
      const stored = await storage.claimFirstUserBootstrap(uppercaseClaim);
      expect(stored.tenantId).toBe(TENANT);
      expect(storage.getFirstUserBootstrapPath(TENANT.toUpperCase())).toBe(
        storage.getFirstUserBootstrapPath(TENANT),
      );

      const originalPath = storage.getFirstUserBootstrapPath(TENANT);
      const movedPath = storage.getFirstUserBootstrapPath(otherTenant);
      await fs.copyFile(originalPath, movedPath);
      await expect(storage.getFirstUserBootstrapReceipt(otherTenant)).rejects.toThrow(
        /tenant does not match its filename/i,
      );
      await expect(storage.getAllUsers()).rejects.toThrow(/moved or renamed/i);
    } finally {
      await storage.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});

describe('FileStorageAdapter 0.7 migration reconciliation', () => {
  it('atomically reconciles one legacy owner before invitation user creation', async () => {
    const fixture = await copyLegacyFileFixture('tinyland-auth-legacy-v07-');
    const config = { authDir: fixture.authDir, totpDir: fixture.totpDir };
    const markerPath = path.join(
      fixture.totpDir,
      'first-user-bootstrap-v0.7-reconciliation.json',
    );
    const storage = new FileStorageAdapter(config);
    await storage.init();

    try {
      expect(await storage.getAllUsers()).toHaveLength(2);
      expect(await storage.getFirstUserBootstrapReceipt(TENANT)).toBeNull();

      const invited = await storage.createUser(makeLegacyInvitee('legacy_invitee'));
      expect(invited.handle).toBe('legacy_invitee');
      expect(await storage.getAllUsers()).toHaveLength(3);

      const markerText = await fs.readFile(markerPath, 'utf8');
      expect(JSON.parse(markerText)).toMatchObject({
        version: 1,
        status: 'legacy-reconciled',
        sourceVersion: '0.7',
        owner: {
          id: 'legacy-owner-001',
          handle: 'legacy_owner',
        },
        reconciledAt: expect.any(String),
      });
      expect((await fs.readdir(fixture.totpDir)).some((entry) => entry.endsWith('.tmp')))
        .toBe(false);
      await expect(storage.deleteUser('legacy-owner-001')).rejects.toThrow(
        /legacy.*owner/i,
      );
      await storage.close();

      const reopened = new FileStorageAdapter(config);
      await reopened.init();
      await expect(reopened.createUser(makeLegacyInvitee('second_invitee')))
        .resolves.toMatchObject({ handle: 'second_invitee' });
      expect(await fs.readFile(markerPath, 'utf8')).toBe(markerText);
      await reopened.close();
    } finally {
      await storage.close();
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });

  it('fails closed when a legacy file has ambiguous active owners', async () => {
    const fixture = await copyLegacyFileFixture('tinyland-auth-legacy-ambiguous-');
    const usersPath = path.join(fixture.authDir, 'admin-users.json');
    const users = JSON.parse(await fs.readFile(usersPath, 'utf8')) as AdminUser[];
    users.push({
      ...users[0],
      id: 'legacy-owner-002',
      handle: 'second_legacy_owner',
      email: 'second-owner@example.test',
    });
    await fs.writeFile(usersPath, JSON.stringify(users, null, 2), 'utf8');
    const markerPath = path.join(
      fixture.totpDir,
      'first-user-bootstrap-v0.7-reconciliation.json',
    );
    const storage = new FileStorageAdapter({
      authDir: fixture.authDir,
      totpDir: fixture.totpDir,
    });
    await storage.init();

    try {
      await expect(storage.createUser(makeLegacyInvitee('blocked_invitee')))
        .rejects.toThrow(/exactly one active super_admin/i);
      expect(await storage.getAllUsers()).toHaveLength(3);
      await expect(fs.readFile(markerPath, 'utf8')).rejects.toMatchObject({
        code: 'ENOENT',
      });
    } finally {
      await storage.close();
      await fs.rm(fixture.root, { recursive: true, force: true });
    }
  });
});

describe('framework-neutral first-user bootstrap conformance runner', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('fails certification for malformed or mismatched adapter returns', async () => {
    const otherTenant = '87654321-4321-4321-8321-cba987654321';
    const adversaries: Array<{
      name: string;
      wrap(storage: MemoryStorageAdapter): IStorageAdapter;
    }> = [
      {
        name: 'empty claim',
        wrap: (storage) => overrideBootstrapBoundary(storage, {
          claimFirstUserBootstrap: async (claim) => {
            await storage.claimFirstUserBootstrap(claim);
            return {} as never;
          },
        }),
      },
      {
        name: 'wrong tenant claim',
        wrap: (storage) => overrideBootstrapBoundary(storage, {
          claimFirstUserBootstrap: async (claim) => ({
            ...(await storage.claimFirstUserBootstrap(claim)),
            tenantId: otherTenant,
          }),
        }),
      },
      {
        name: 'wrong actor claim',
        wrap: (storage) => overrideBootstrapBoundary(storage, {
          claimFirstUserBootstrap: async (claim) => {
            const returned = await storage.claimFirstUserBootstrap(claim);
            return {
              ...returned,
              actor: { ...returned.actor, id: 'different-claimed-actor' },
            };
          },
        }),
      },
      {
        name: 'drifted claim timestamp',
        wrap: (storage) => overrideBootstrapBoundary(storage, {
          claimFirstUserBootstrap: async (claim) => {
            const returned = await storage.claimFirstUserBootstrap(claim);
            return {
              ...returned,
              claimedAt: new Date(Date.parse(returned.claimedAt) + 1).toISOString(),
            };
          },
        }),
      },
      {
        name: 'non-binding expired claim',
        wrap: (storage) => overrideBootstrapBoundary(storage, {
          claimFirstUserBootstrap: async (claim) =>
            Date.parse(claim.claimedAt) < Date.now() - 600_000
              ? structuredClone(claim)
              : storage.claimFirstUserBootstrap(claim),
        }),
      },
      {
        name: 'ordinary first-user bypass',
        wrap: (storage) => overrideBootstrapBoundary(storage, {
          createUser: async (user) => ({
            ...user,
            id: 'forged-ordinary-first-user',
          }),
        }),
      },
      {
        name: 'wrong finalization receipt',
        wrap: (storage) => overrideBootstrapBoundary(storage, {
          finalizeFirstUserBootstrap: async (finalization) => ({
            ...(await storage.finalizeFirstUserBootstrap(finalization)),
            materialDigest: '0'.repeat(64),
          }),
        }),
      },
      {
        name: 'forged finalization receipt claim time',
        wrap: (storage) => overrideBootstrapBoundary(storage, {
          finalizeFirstUserBootstrap: async (finalization) => ({
            ...(await storage.finalizeFirstUserBootstrap(finalization)),
            claimedAt: '2000-01-01T00:00:00.000Z',
          }),
        }),
      },
      {
        name: 'wrong stored receipt tenant',
        wrap: (storage) => overrideBootstrapBoundary(storage, {
          getFirstUserBootstrapReceipt: async (tenantId) => {
            const receipt = await storage.getFirstUserBootstrapReceipt(tenantId);
            return receipt === null ? null : { ...receipt, tenantId: otherTenant };
          },
        }),
      },
      {
        name: 'forged stored receipt claim time',
        wrap: (storage) => overrideBootstrapBoundary(storage, {
          getFirstUserBootstrapReceipt: async (tenantId) => {
            const receipt = await storage.getFirstUserBootstrapReceipt(tenantId);
            return receipt === null
              ? null
              : { ...receipt, claimedAt: '2000-01-01T00:00:00.000Z' };
          },
        }),
      },
    ];

    for (const adversary of adversaries) {
      await expect(runFirstUserBootstrapStorageConformance(async () => {
        const storage = new MemoryStorageAdapter();
        return clockControlledHarness(adversary.wrap(storage));
      }), adversary.name).rejects.toMatchObject({
        name: 'FirstUserBootstrapConformanceError',
      });
    }
  });

  it('rejects an adapter that accepts finalization at 600001 ms', async () => {
    await expect(runFirstUserBootstrapStorageConformance(async () => {
      const storage = new MemoryStorageAdapter();
      let activeClaim: InertFirstUserClaim | null = null;
      const boundaryBlind = overrideBootstrapBoundary(storage, {
        claimFirstUserBootstrap: async (claim) => {
          const returned = await storage.claimFirstUserBootstrap(claim);
          activeClaim = structuredClone(returned);
          return returned;
        },
        finalizeFirstUserBootstrap: async (finalization) => {
          try {
            return await storage.finalizeFirstUserBootstrap(finalization);
          } catch (error) {
            if (
              activeClaim !== null &&
              Date.now() === Date.parse(activeClaim.claimedAt) + 600_001
            ) {
              return createFirstUserBootstrapReceipt(activeClaim, finalization);
            }
            throw error;
          }
        },
      });
      return clockControlledHarness(boundaryBlind);
    })).rejects.toMatchObject({
      name: 'FirstUserBootstrapConformanceError',
      caseName: 'finalization is rejected at 600001 ms',
    });
  });

  it('runs against the memory adapter', async () => {
    const tenants: string[] = [];
    const results = await runFirstUserBootstrapStorageConformance(async (tenantId) => {
      tenants.push(tenantId);
      return clockControlledHarness(new MemoryStorageAdapter());
    });
    expect(results).toHaveLength(28);
    expect(new Set(tenants).size).toBe(28);
    expect(results.map(({ name }) => name)).toEqual(expect.arrayContaining([
      'ordinary creation cannot create the first user',
      'ordinary creation racing finalization cannot steal first authority',
      'bootstrap claim revokes pre-bootstrap privileged sessions',
      'concurrent conflicting finalizations have one winner',
      'finalization succeeds at 599999 ms',
      'finalization succeeds at 600000 ms',
      'finalization is rejected at 600001 ms',
    ]));
    expect(
      tenants.every((tenantId) =>
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
          tenantId,
        ),
      ),
    ).toBe(true);
  });

  it('runs against the file adapter', async () => {
    const results = await runFirstUserBootstrapStorageConformance(async (_tenantId) => {
      const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tinyland-auth-runner-'));
      return clockControlledHarness(
        new FileStorageAdapter({
          authDir: path.join(root, 'auth'),
          totpDir: path.join(root, 'totp'),
        }),
        async () => fs.rm(root, { recursive: true, force: true }),
      );
    });
    expect(results).toHaveLength(28);
  });
});
