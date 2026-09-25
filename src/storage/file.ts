








import { promises as fs } from 'fs';
import path from 'path';
import { createHash, randomBytes, randomUUID } from 'crypto';
import type { IStorageAdapter, StorageAdapterConfig, AuditEventFilters } from './interface.js';
import type {
  AdminUser,
  Session,
  SessionMetadata,
  AdminInvitation,
  BackupCodeSet,
  AuditEvent,
  EncryptedTOTPSecret,
} from '../types/index.js';
import {
  FirstUserBootstrapConflictError,
  FirstUserBootstrapValidationError,
  canonicalizeFirstUserBootstrapFinalization,
  canonicalizeFirstUserBootstrapFinalizationPayload,
  canonicalizeInertFirstUserClaim,
  canonicalizeStructuralInertFirstUserClaim,
  cloneBootstrapValue,
  createFirstUserBootstrapReceipt,
  firstUserBootstrapMaterialDigest,
  firstUserBootstrapValueDigest,
  firstUserBootstrapValuesEqual,
  isExpiredInertFirstUserClaim,
  normalizeFirstUserBootstrapTenantId,
  parseFirstUserBootstrapReceipt,
  type FirstUserBootstrapFinalization,
  type FirstUserBootstrapReceipt,
  type InertFirstUserClaim,
} from './firstUserBootstrap.js';

interface ClaimedFirstUserBootstrapRecord {
  version: 1;
  status: 'claimed';
  tenantId: string;
  claim: InertFirstUserClaim;
}

interface CompletedFirstUserBootstrapRecord {
  version: 1;
  status: 'completed';
  tenantId: string;
  claim: InertFirstUserClaim;
  receipt: FirstUserBootstrapReceipt;
  initialState: FirstUserBootstrapFinalization;
}

type FirstUserBootstrapRecord =
  | ClaimedFirstUserBootstrapRecord
  | CompletedFirstUserBootstrapRecord;

interface LegacyFirstUserBootstrapReconciliation {
  version: 1;
  status: 'legacy-reconciled';
  sourceVersion: '0.7';
  owner: {
    id: string;
    handle: string;
  };
  reconciledAt: string;
}

type FirstUserBootstrapLockSlot = 0 | 1;

interface FirstUserBootstrapLockSlotState {
  slot: FirstUserBootstrapLockSlot;
  ownerPath: string;
  heldPath: string;
  releasingPath: string;
  releasePath: string;
  ownerStat: Awaited<ReturnType<typeof fs.lstat>> | null;
  heldStat: Awaited<ReturnType<typeof fs.lstat>> | null;
  releasingStat: Awaited<ReturnType<typeof fs.lstat>> | null;
  releaseStat: Awaited<ReturnType<typeof fs.lstat>> | null;
}

type FirstUserBootstrapLockState =
  | {
      kind: 'available';
      slot: FirstUserBootstrapLockSlot;
      retired: FirstUserBootstrapLockSlotState | null;
    }
  | { kind: 'blocked' }
  | { kind: 'retry' };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function parseLegacyFirstUserBootstrapReconciliation(
  value: unknown,
): LegacyFirstUserBootstrapReconciliation {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'status',
      'sourceVersion',
      'owner',
      'reconciledAt',
    ]) ||
    value.version !== 1 ||
    value.status !== 'legacy-reconciled' ||
    value.sourceVersion !== '0.7' ||
    !isRecord(value.owner) ||
    !hasExactKeys(value.owner, ['id', 'handle']) ||
    typeof value.owner.id !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value.owner.id) ||
    typeof value.owner.handle !== 'string' ||
    !/^[a-zA-Z][a-zA-Z0-9_-]{2,29}$/.test(value.owner.handle) ||
    typeof value.reconciledAt !== 'string'
  ) {
    throw new FirstUserBootstrapValidationError(
      'Corrupted legacy first-user bootstrap reconciliation marker',
    );
  }
  const reconciledAt = Date.parse(value.reconciledAt);
  if (
    !Number.isFinite(reconciledAt) ||
    new Date(reconciledAt).toISOString() !== value.reconciledAt
  ) {
    throw new FirstUserBootstrapValidationError(
      'Corrupted legacy first-user bootstrap reconciliation timestamp',
    );
  }
  return {
    version: 1,
    status: 'legacy-reconciled',
    sourceVersion: '0.7',
    owner: {
      id: value.owner.id,
      handle: value.owner.handle,
    },
    reconciledAt: value.reconciledAt,
  };
}

function parseFirstUserBootstrapRecord(
  value: unknown,
  expectedTenantId?: string,
): FirstUserBootstrapRecord {
  if (!isRecord(value) || value.version !== 1 || !isRecord(value.claim)) {
    throw new FirstUserBootstrapValidationError(
      'Corrupted first-user bootstrap record',
    );
  }
  const tenantId = normalizeFirstUserBootstrapTenantId(value.tenantId);
  if (value.tenantId !== tenantId || (expectedTenantId !== undefined && tenantId !== expectedTenantId)) {
    throw new FirstUserBootstrapValidationError(
      'First-user bootstrap record tenant does not match its filename',
    );
  }

  const claim = canonicalizeStructuralInertFirstUserClaim(value.claim);
  if (
    claim.tenantId !== tenantId ||
    firstUserBootstrapValueDigest(value.claim) !== firstUserBootstrapValueDigest(claim)
  ) {
    throw new FirstUserBootstrapValidationError(
      'Corrupted inert first-user bootstrap claim',
    );
  }

  if (value.status === 'claimed') {
    if (!hasExactKeys(value, ['version', 'status', 'tenantId', 'claim'])) {
      throw new FirstUserBootstrapValidationError(
        'Corrupted claimed first-user bootstrap record shape',
      );
    }
    return { version: 1, status: 'claimed', tenantId, claim };
  }
  if (
    value.status !== 'completed' ||
    !hasExactKeys(value, [
      'version',
      'status',
      'tenantId',
      'claim',
      'receipt',
      'initialState',
    ]) ||
    !isRecord(value.receipt) ||
    !isRecord(value.initialState)
  ) {
    throw new FirstUserBootstrapValidationError(
      'Corrupted first-user bootstrap completion record',
    );
  }

  const finalizedAt = Date.parse(String(value.initialState.finalizedAt));
  if (!Number.isFinite(finalizedAt)) {
    throw new FirstUserBootstrapValidationError(
      'Corrupted first-user bootstrap finalization timestamp',
    );
  }
  const initialState = canonicalizeFirstUserBootstrapFinalization(
    claim,
    value.initialState,
    finalizedAt,
  );
  if (
    initialState.tenantId !== tenantId ||
    !firstUserBootstrapValuesEqual(value.initialState, initialState)
  ) {
    throw new FirstUserBootstrapValidationError(
      'Corrupted canonical first-user bootstrap finalization',
    );
  }
  let receipt: FirstUserBootstrapReceipt;
  try {
    receipt = parseFirstUserBootstrapReceipt(value.receipt, {
      claim,
      finalization: initialState,
    });
    if (
      firstUserBootstrapValueDigest(value.receipt) !==
      firstUserBootstrapValueDigest(receipt)
    ) {
      throw new FirstUserBootstrapValidationError(
        'Bootstrap receipt is not stored in canonical form',
      );
    }
  } catch (error) {
    throw new FirstUserBootstrapValidationError(
      `Corrupted immutable first-user bootstrap receipt: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  return {
    version: 1,
    status: 'completed',
    tenantId,
    claim,
    receipt,
    initialState,
  };
}

export interface FileStorageConfig extends StorageAdapterConfig {
  
  authDir: string;
  
  totpDir: string;
  
  sessionMaxAge: number;

  /** Bounded wait before an existing bootstrap lock fails closed. */
  firstUserBootstrapLockTimeoutMs: number;

  /** Retry interval while waiting for the bootstrap lock. */
  firstUserBootstrapLockRetryMs: number;
}

const DEFAULT_CONFIG: FileStorageConfig = {
  authDir: 'content/auth',
  totpDir: '.totp-secrets',
  sessionMaxAge: 7 * 24 * 60 * 60 * 1000, 
  firstUserBootstrapLockTimeoutMs: 5000,
  firstUserBootstrapLockRetryMs: 10,
};
















export class FileStorageAdapter implements IStorageAdapter {
  private config: FileStorageConfig;
  private basePath: string;
  
  private locks = new Map<string, Promise<void>>();

  constructor(config: Partial<FileStorageConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    for (const [label, value] of [
      ['firstUserBootstrapLockTimeoutMs', this.config.firstUserBootstrapLockTimeoutMs],
      ['firstUserBootstrapLockRetryMs', this.config.firstUserBootstrapLockRetryMs],
    ] as const) {
      if (!Number.isSafeInteger(value) || value <= 0) {
        throw new FirstUserBootstrapValidationError(`${label} must be a positive safe integer`);
      }
    }
    this.basePath = config.basePath
      ? path.resolve(config.basePath)
      : process.cwd();
  }

  
  
  

  async init(): Promise<void> {
    
    await this.ensureDir(this.getPath('admin-users.json'));
    await this.ensureDir(this.getPath('sessions.json'));
    await this.ensureDir(this.getPath('invites.json'));
    await this.ensureDir(this.getPath('logs/audit.json'));
    await this.ensureDir(path.join(this.basePath, this.config.totpDir, 'backup-codes', '.gitkeep'));
    await this.ensureDir(path.join(this.getFirstUserBootstrapDir(), '.gitkeep'));
  }

  async close(): Promise<void> {
    
  }

  async hasUsers(): Promise<boolean> {
    return (await this.getAllUsers()).length > 0;
  }

  async getAllSessions(): Promise<Session[]> {
    return this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
  }

  
  
  

  private getPath(filename: string): string {
    return path.resolve(this.basePath, this.config.authDir, filename);
  }

  private getTotpPath(handle: string): string {
    return path.resolve(this.basePath, this.config.totpDir, `${handle}.json`);
  }

  private getBackupCodesPath(userId: string): string {
    return path.resolve(this.basePath, this.config.totpDir, 'backup-codes', `${userId}.json`);
  }

  getFirstUserBootstrapPath(tenantId: string): string {
    const canonicalTenantId = normalizeFirstUserBootstrapTenantId(tenantId);
    const tenantKey = createHash('sha256').update(canonicalTenantId).digest('hex');
    return path.resolve(
      this.basePath,
      this.config.totpDir,
      'first-user-bootstrap',
      `${tenantKey}.json`,
    );
  }

  private getFirstUserBootstrapDir(): string {
    return path.resolve(this.basePath, this.config.totpDir, 'first-user-bootstrap');
  }

  private getFirstUserBootstrapLockDir(): string {
    return path.resolve(this.basePath, this.config.totpDir, '.first-user-bootstrap.lock');
  }

  private getLegacyFirstUserBootstrapReconciliationPath(): string {
    return path.resolve(
      this.basePath,
      this.config.totpDir,
      'first-user-bootstrap-v0.7-reconciliation.json',
    );
  }

  private async ensureDir(filePath: string): Promise<void> {
    const dir = path.dirname(filePath);
    try {
      await fs.access(dir);
    } catch {
      await fs.mkdir(dir, { recursive: true });
    }
  }

  private async readJsonFile<T>(filePath: string, defaultValue: T): Promise<T> {
    try {
      await this.ensureDir(filePath);
      const content = await fs.readFile(filePath, 'utf8');
      return JSON.parse(content) as T;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return defaultValue;
      }
      throw error;
    }
  }

  private async readOptionalJsonFile<T>(
    filePath: string,
  ): Promise<{ exists: boolean; value: T | null }> {
    try {
      await this.ensureDir(filePath);
      const content = await fs.readFile(filePath, 'utf8');
      return { exists: true, value: JSON.parse(content) as T | null };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return { exists: false, value: null };
      }
      throw error;
    }
  }

  private async removeFileIfExists(filePath: string): Promise<boolean> {
    try {
      await fs.unlink(filePath);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
      throw error;
    }
  }

  



  private async writeJsonFile<T>(filePath: string, data: T): Promise<void> {
    await this.withFileLock(filePath, async () => {
      await this.writeJsonFileAtomic(filePath, data);
    });
  }

  



  private async writeJsonFileAtomic<T>(filePath: string, data: T): Promise<void> {
    await this.ensureDir(filePath);
    const tempPath = `${filePath}.${Date.now()}.${randomBytes(4).toString('hex')}.tmp`;

    try {
      const temp = await fs.open(tempPath, 'wx', 0o600);
      try {
        await temp.writeFile(JSON.stringify(data, null, 2), 'utf8');
        await temp.sync();
      } finally {
        await temp.close();
      }
      await fs.rename(tempPath, filePath);

      const directory = await fs.open(path.dirname(filePath), 'r');
      try {
        await directory.sync();
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== 'EINVAL' && code !== 'ENOTSUP' && code !== 'EBADF') {
          throw error;
        }
      } finally {
        await directory.close();
      }
    } catch (error) {
      
      try { await fs.unlink(tempPath); } catch {  }
      throw error;
    }
  }

  



  private async withFileLock<T>(filePath: string, operation: () => Promise<T>): Promise<T> {
    
    const existing = this.locks.get(filePath);
    if (existing) {
      await existing;
    }

    
    let resolve: () => void;
    const lockPromise = new Promise<void>(r => { resolve = r; });
    this.locks.set(filePath, lockPromise);

    try {
      return await operation();
    } finally {
      resolve!();
      this.locks.delete(filePath);
    }
  }

  private async withFirstUserBootstrapLock<T>(
    operation: () => Promise<T>,
  ): Promise<T> {
    const lockDir = this.getFirstUserBootstrapLockDir();
    try {
      await fs.mkdir(lockDir, { recursive: true, mode: 0o700 });
    } catch (error) {
      throw new FirstUserBootstrapConflictError(
        `Cannot initialize first-user bootstrap lock directory; operator recovery required: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    const deadline = Date.now() + this.config.firstUserBootstrapLockTimeoutMs;
    while (true) {
      const state = await this.inspectFirstUserBootstrapLock(lockDir);
      if (state.kind !== 'available') {
        await this.waitForFirstUserBootstrapLock(deadline);
        continue;
      }

      const ownerPath = path.join(lockDir, `${state.slot}.owner`);
      const heldPath = path.join(lockDir, `${state.slot}.held`);
      const releasingPath = path.join(lockDir, `${state.slot}.releasing`);
      const releasePath = path.join(lockDir, `${state.slot}.released`);
      let lockHandle: Awaited<ReturnType<typeof fs.open>>;
      try {
        lockHandle = await fs.open(ownerPath, 'wx', 0o600);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
        await this.waitForFirstUserBootstrapLock(deadline);
        continue;
      }

      // From this point onward the finally block releases only with a
      // handle-derived inode identity; otherwise it leaves the path untouched.
      let ownedStat: { dev: number; ino: number } | undefined;
      try {
        ownedStat = await lockHandle.stat();
        await fs.link(ownerPath, heldPath);
        if (state.retired) {
          await this.removeRetiredFirstUserBootstrapLock(state.retired);
        }
        await lockHandle.writeFile(JSON.stringify({
          version: 1,
          pid: process.pid,
          token: randomBytes(32).toString('hex'),
          createdAt: new Date().toISOString(),
        }), 'utf8');
        await lockHandle.sync();
        await this.syncDirectory(lockDir);
        await this.assertFirstUserBootstrapLockInode(ownerPath, ownedStat);
        return await operation();
      } finally {
        let releaseError: unknown;
        try {
          if (!ownedStat) {
            try {
              ownedStat = await lockHandle.stat();
            } catch (error) {
              releaseError = new FirstUserBootstrapConflictError(
                `Cannot authenticate first-user bootstrap lock owner for release; ` +
                `the owner path was left untouched for attended recovery: ${
                  error instanceof Error ? error.message : String(error)
                }`,
              );
            }
          }
          if (ownedStat) {
            await this.releaseFirstUserBootstrapLock(
              lockDir,
              ownerPath,
              heldPath,
              releasingPath,
              releasePath,
              ownedStat,
            );
          }
        } catch (error) {
          releaseError ??= error;
        }
        try {
          await lockHandle.close();
        } catch (error) {
          releaseError ??= error;
        }
        if (releaseError) throw releaseError;
      }
    }
  }

  private getFirstUserBootstrapLockSlotPaths(
    lockDir: string,
    slot: FirstUserBootstrapLockSlot,
  ): {
    ownerPath: string;
    heldPath: string;
    releasingPath: string;
    releasePath: string;
  } {
    return {
      ownerPath: path.join(lockDir, `${slot}.owner`),
      heldPath: path.join(lockDir, `${slot}.held`),
      releasingPath: path.join(lockDir, `${slot}.releasing`),
      releasePath: path.join(lockDir, `${slot}.released`),
    };
  }

  private async lstatFirstUserBootstrapLockPath(
    filePath: string,
  ): Promise<Awaited<ReturnType<typeof fs.lstat>> | null> {
    try {
      return await fs.lstat(filePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    }
  }

  private async inspectFirstUserBootstrapLock(
    lockDir: string,
  ): Promise<FirstUserBootstrapLockState> {
    const firstSample = await this.sampleFirstUserBootstrapLockSlots(lockDir);
    const slots = await this.sampleFirstUserBootstrapLockSlots(lockDir);
    if (!this.firstUserBootstrapLockSamplesMatch(firstSample, slots)) {
      return { kind: 'retry' };
    }

    for (const slot of slots) {
      if (
        (slot.releaseStat || slot.releasingStat || slot.heldStat) &&
        !slot.ownerStat
      ) {
        return { kind: 'retry' };
      }
      if (
        (slot.ownerStat && !slot.ownerStat.isFile()) ||
        (slot.heldStat && !slot.heldStat.isFile()) ||
        (slot.releasingStat && !slot.releasingStat.isFile()) ||
        (slot.releaseStat && !slot.releaseStat.isFile()) ||
        (slot.ownerStat &&
          slot.heldStat &&
          (slot.ownerStat.dev !== slot.heldStat.dev ||
            slot.ownerStat.ino !== slot.heldStat.ino)) ||
        (slot.ownerStat &&
          slot.releasingStat &&
          (slot.ownerStat.dev !== slot.releasingStat.dev ||
            slot.ownerStat.ino !== slot.releasingStat.ino)) ||
        (slot.ownerStat &&
          slot.releaseStat &&
          (slot.ownerStat.dev !== slot.releaseStat.dev ||
            slot.ownerStat.ino !== slot.releaseStat.ino)) ||
        (slot.releaseStat && !slot.releasingStat)
      ) {
        throw new FirstUserBootstrapConflictError(
          'First-user bootstrap lock ownership is ambiguous; attended operator recovery required',
        );
      }
    }

    const active = slots.filter((slot) => slot.ownerStat && !slot.releaseStat);
    const released = slots.filter((slot) => slot.ownerStat && slot.releaseStat);
    if (active.length === 1) return { kind: 'blocked' };
    if (active.length > 1 || released.length > 1) {
      throw new FirstUserBootstrapConflictError(
        'First-user bootstrap lock slots are ambiguous; attended operator recovery required',
      );
    }
    if (released.length === 0) {
      return { kind: 'available', slot: 0, retired: null };
    }
    const retired = released[0];
    return {
      kind: 'available',
      slot: retired.slot === 0 ? 1 : 0,
      retired,
    };
  }

  private async sampleFirstUserBootstrapLockSlots(
    lockDir: string,
  ): Promise<FirstUserBootstrapLockSlotState[]> {
    return Promise.all(([0, 1] as const).map(async (slot) => {
      const { ownerPath, heldPath, releasingPath, releasePath } =
        this.getFirstUserBootstrapLockSlotPaths(lockDir, slot);
      const [ownerStat, heldStat, releasingStat, releaseStat] = await Promise.all([
        this.lstatFirstUserBootstrapLockPath(ownerPath),
        this.lstatFirstUserBootstrapLockPath(heldPath),
        this.lstatFirstUserBootstrapLockPath(releasingPath),
        this.lstatFirstUserBootstrapLockPath(releasePath),
      ]);
      return {
        slot,
        ownerPath,
        heldPath,
        releasingPath,
        releasePath,
        ownerStat,
        heldStat,
        releasingStat,
        releaseStat,
      };
    }));
  }

  private firstUserBootstrapLockSamplesMatch(
    first: FirstUserBootstrapLockSlotState[],
    second: FirstUserBootstrapLockSlotState[],
  ): boolean {
    const statMatches = (
      left: Awaited<ReturnType<typeof fs.lstat>> | null,
      right: Awaited<ReturnType<typeof fs.lstat>> | null,
    ): boolean =>
      left === null || right === null
        ? left === right
        : left.dev === right.dev &&
          left.ino === right.ino &&
          left.isFile() === right.isFile();

    return first.length === second.length && first.every((left, index) => {
      const right = second[index];
      return left.slot === right.slot &&
        statMatches(left.ownerStat, right.ownerStat) &&
        statMatches(left.heldStat, right.heldStat) &&
        statMatches(left.releasingStat, right.releasingStat) &&
        statMatches(left.releaseStat, right.releaseStat);
    });
  }

  private async removeRetiredFirstUserBootstrapLock(
    retired: FirstUserBootstrapLockSlotState,
  ): Promise<void> {
    const [ownerStat, heldStat, releasingStat, releaseStat] = await Promise.all([
      fs.lstat(retired.ownerPath),
      this.lstatFirstUserBootstrapLockPath(retired.heldPath),
      fs.lstat(retired.releasingPath),
      fs.lstat(retired.releasePath),
    ]);
    if (
      !ownerStat.isFile() ||
      !releasingStat.isFile() ||
      !releaseStat.isFile() ||
      ownerStat.dev !== releasingStat.dev ||
      ownerStat.ino !== releasingStat.ino ||
      ownerStat.dev !== releaseStat.dev ||
      ownerStat.ino !== releaseStat.ino ||
      (heldStat &&
        (!heldStat.isFile() ||
          ownerStat.dev !== heldStat.dev ||
          ownerStat.ino !== heldStat.ino))
    ) {
      throw new FirstUserBootstrapConflictError(
        'Retired first-user bootstrap lock ownership is ambiguous; attended operator recovery required',
      );
    }
    // The other slot is already this process's active owner. Therefore this
    // released slot cannot belong to a live owner and is safe to compact.
    await fs.unlink(retired.ownerPath);
    await fs.unlink(retired.releasingPath);
    await fs.unlink(retired.releasePath);
    if (heldStat) await fs.unlink(retired.heldPath);
  }

  private async releaseFirstUserBootstrapLock(
    lockDir: string,
    ownerPath: string,
    heldPath: string,
    releasingPath: string,
    releasePath: string,
    ownedStat: { dev: number; ino: number },
  ): Promise<void> {
    try {
      await this.assertFirstUserBootstrapLockInode(ownerPath, ownedStat);
    } catch {
      // A transient verification failure during acquisition must not leave
      // an active owner. A real replacement fails the confirming check too.
      await this.assertFirstUserBootstrapLockInode(ownerPath, ownedStat);
    }
    let releaseSource = ownerPath;
    try {
      await this.assertFirstUserBootstrapLockInode(heldPath, ownedStat);
      releaseSource = heldPath;
    } catch {
      await this.assertFirstUserBootstrapLockInode(ownerPath, ownedStat);
    }
    try {
      await fs.link(releaseSource, releasingPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      await this.assertFirstUserBootstrapLockInode(releasingPath, ownedStat);
    }
    await this.syncDirectory(lockDir);
    await this.assertFirstUserBootstrapLockInode(ownerPath, ownedStat);
    await this.assertFirstUserBootstrapLockInode(releasingPath, ownedStat);
    if (releaseSource === heldPath) {
      await this.assertFirstUserBootstrapLockInode(heldPath, ownedStat);
    }
    // This no-replace hard link is the final release publication. Once it is
    // visible, contenders may compact the slot, so release performs no more
    // pathname reads or deletions.
    await fs.link(releasingPath, releasePath);
  }

  private async waitForFirstUserBootstrapLock(deadline: number): Promise<void> {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new FirstUserBootstrapConflictError(
        'Timed out acquiring first-user bootstrap storage lock',
      );
    }
    await new Promise((resolve) =>
      setTimeout(
        resolve,
        Math.min(this.config.firstUserBootstrapLockRetryMs, remaining),
      ),
    );
  }

  private async assertFirstUserBootstrapLockInode(
    filePath: string,
    ownedStat: { dev: number; ino: number },
  ): Promise<void> {
    let pathStat: Awaited<ReturnType<typeof fs.lstat>>;
    try {
      pathStat = await fs.lstat(filePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new FirstUserBootstrapConflictError(
          'First-user bootstrap lock ownership artifact disappeared; operator recovery required',
        );
      }
      throw error;
    }
    if (
      !pathStat.isFile() ||
      pathStat.dev !== ownedStat.dev ||
      pathStat.ino !== ownedStat.ino
    ) {
      throw new FirstUserBootstrapConflictError(
        'First-user bootstrap lock ownership changed during the operation; operator recovery required',
      );
    }
  }

  private async syncDirectory(directoryPath: string): Promise<void> {
    const directory = await fs.open(directoryPath, 'r');
    try {
      await directory.sync();
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'EINVAL' && code !== 'ENOTSUP' && code !== 'EBADF') throw error;
    } finally {
      await directory.close();
    }
  }

  private async readFirstUserBootstrapRecord(
    tenantId: string,
  ): Promise<FirstUserBootstrapRecord | null> {
    const canonicalTenantId = normalizeFirstUserBootstrapTenantId(tenantId);
    const stored = await this.readOptionalJsonFile<unknown>(
      this.getFirstUserBootstrapPath(canonicalTenantId),
    );
    if (!stored.exists) return null;
    return parseFirstUserBootstrapRecord(stored.value, canonicalTenantId);
  }

  private async readLegacyFirstUserBootstrapReconciliation(): Promise<
    LegacyFirstUserBootstrapReconciliation | null
  > {
    const stored = await this.readOptionalJsonFile<unknown>(
      this.getLegacyFirstUserBootstrapReconciliationPath(),
    );
    if (!stored.exists) return null;
    return parseLegacyFirstUserBootstrapReconciliation(stored.value);
  }

  private async getAllFirstUserBootstrapRecords(): Promise<FirstUserBootstrapRecord[]> {
    let entries: string[];
    try {
      entries = await fs.readdir(this.getFirstUserBootstrapDir());
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    }

    const records: FirstUserBootstrapRecord[] = [];
    for (const entry of entries.sort()) {
      if (!entry.endsWith('.json')) continue;
      const value = await this.readJsonFile<unknown | null>(
        path.join(this.getFirstUserBootstrapDir(), entry),
        null,
      );
      const record = parseFirstUserBootstrapRecord(value);
      if (path.basename(this.getFirstUserBootstrapPath(record.tenantId)) !== entry) {
        throw new FirstUserBootstrapValidationError(
          'First-user bootstrap record was moved or renamed under another tenant filename',
        );
      }
      records.push(record);
    }
    return records;
  }

  private async getBootstrapRecordForActor(
    actorId?: string,
    handle?: string,
  ): Promise<FirstUserBootstrapRecord | null> {
    const records = await this.getAllFirstUserBootstrapRecords();
    return records.find((record) =>
      (actorId !== undefined && record.claim.actor.id === actorId) ||
      (handle !== undefined &&
        record.claim.actor.handle.toLowerCase() === handle.toLowerCase()),
    ) ?? null;
  }

  private async readCurrentUsers(): Promise<AdminUser[]> {
    return this.readJsonFile<AdminUser[]>(this.getPath('admin-users.json'), []);
  }

  private selectLegacyFirstUserOwner(users: AdminUser[]): AdminUser {
    const ids = new Set<string>();
    const handles = new Set<string>();
    for (const user of users) {
      if (
        !isRecord(user) ||
        typeof user.id !== 'string' ||
        user.id.length === 0 ||
        typeof user.handle !== 'string' ||
        user.handle.length === 0
      ) {
        throw new FirstUserBootstrapValidationError(
          'Legacy 0.7 user storage contains an invalid identity',
        );
      }
      const handle = user.handle.toLowerCase();
      if (ids.has(user.id) || handles.has(handle)) {
        throw new FirstUserBootstrapConflictError(
          'Legacy 0.7 user storage contains duplicate identities',
        );
      }
      ids.add(user.id);
      handles.add(handle);
    }

    const owners = users.filter(
      (user) =>
        user.role === 'super_admin' &&
        user.isActive === true &&
        user.isLocked !== true,
    );
    if (owners.length !== 1) {
      throw new FirstUserBootstrapConflictError(
        'Legacy 0.7 reconciliation requires exactly one active super_admin owner',
      );
    }
    return owners[0];
  }

  private async ensureLegacyFirstUserBootstrapReconciliation(
    users: AdminUser[],
  ): Promise<LegacyFirstUserBootstrapReconciliation> {
    const existing = await this.readLegacyFirstUserBootstrapReconciliation();
    if (existing) {
      if (!users.some((user) => user.id === existing.owner.id)) {
        throw new FirstUserBootstrapConflictError(
          'Legacy first-user bootstrap owner is missing from user storage',
        );
      }
      return existing;
    }

    const owner = this.selectLegacyFirstUserOwner(users);
    const marker = parseLegacyFirstUserBootstrapReconciliation({
      version: 1,
      status: 'legacy-reconciled',
      sourceVersion: '0.7',
      owner: {
        id: owner.id,
        handle: owner.handle,
      },
      reconciledAt: new Date().toISOString(),
    });
    await this.writeJsonFileAtomic(
      this.getLegacyFirstUserBootstrapReconciliationPath(),
      marker,
    );
    return marker;
  }

  private async getAllUsersUnlocked(): Promise<AdminUser[]> {
    const users = new Map<string, AdminUser>();
    for (const record of await this.getAllFirstUserBootstrapRecords()) {
      if (record.status === 'completed') {
        users.set(record.initialState.user.id, cloneBootstrapValue(record.initialState.user));
      }
    }
    for (const user of await this.readCurrentUsers()) {
      users.set(user.id, user);
    }
    return Array.from(users.values());
  }

  async claimFirstUserBootstrap(
    claim: InertFirstUserClaim,
  ): Promise<InertFirstUserClaim> {
    const structuralClaim = canonicalizeStructuralInertFirstUserClaim(claim);

    return this.withFirstUserBootstrapLock(async () => {
      if (await this.readLegacyFirstUserBootstrapReconciliation()) {
        throw new FirstUserBootstrapConflictError(
          'First-user bootstrap authority was reconciled from a legacy 0.7 store',
        );
      }
      const existing = await this.readFirstUserBootstrapRecord(structuralClaim.tenantId);
      if (existing) {
        if (
          existing.status === 'claimed' &&
          firstUserBootstrapValueDigest(existing.claim) ===
            firstUserBootstrapValueDigest(structuralClaim)
        ) {
          await this.writeJsonFileAtomic(this.getPath('sessions.json'), []);
          return cloneBootstrapValue(existing.claim);
        }
        if (existing.status === 'completed') {
          throw new FirstUserBootstrapConflictError(
            'First-user bootstrap is already finalized for this tenant',
          );
        }
        if (!isExpiredInertFirstUserClaim(existing.claim)) {
          throw new FirstUserBootstrapConflictError(
            'A different first-user bootstrap claim already exists for this tenant',
          );
        }
      }
      const canonicalClaim = canonicalizeInertFirstUserClaim(structuralClaim);
      const otherRecords = (await this.getAllFirstUserBootstrapRecords()).filter(
        (record) => record.tenantId !== canonicalClaim.tenantId,
      );
      if (otherRecords.length > 0) {
        throw new FirstUserBootstrapConflictError(
          'This file storage root already belongs to another bootstrap tenant',
        );
      }
      if ((await this.getAllUsersUnlocked()).length > 0) {
        throw new FirstUserBootstrapConflictError(
          'First-user bootstrap requires an empty user store',
        );
      }
      const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
      const totp = await this.readOptionalJsonFile<EncryptedTOTPSecret>(
        this.getTotpPath(canonicalClaim.actor.handle),
      );
      const backupCodes = await this.readOptionalJsonFile<BackupCodeSet>(
        this.getBackupCodesPath(canonicalClaim.actor.id),
      );
      if (
        (totp.exists && totp.value !== null) ||
        (backupCodes.exists && backupCodes.value !== null)
      ) {
        throw new FirstUserBootstrapConflictError(
          'Claimed actor already has factor state',
        );
      }

      const record: ClaimedFirstUserBootstrapRecord = {
        version: 1,
        status: 'claimed',
        tenantId: canonicalClaim.tenantId,
        claim: cloneBootstrapValue(canonicalClaim),
      };
      if (sessions.length > 0) {
        await this.writeJsonFileAtomic(this.getPath('sessions.json'), []);
      }
      await this.writeJsonFileAtomic(
        this.getFirstUserBootstrapPath(canonicalClaim.tenantId),
        record,
      );
      return cloneBootstrapValue(record.claim);
    });
  }

  async finalizeFirstUserBootstrap(
    finalization: FirstUserBootstrapFinalization,
  ): Promise<FirstUserBootstrapReceipt> {
    const payload = canonicalizeFirstUserBootstrapFinalizationPayload(finalization);
    return this.withFirstUserBootstrapLock(async () => {
      const record = await this.readFirstUserBootstrapRecord(payload.tenantId);
      if (!record) {
        throw new FirstUserBootstrapConflictError(
          'No active first-user bootstrap claim exists for this tenant',
        );
      }
      if (record.status === 'completed') {
        const canonicalReplay = canonicalizeFirstUserBootstrapFinalization(
          record.claim,
          payload,
          Date.parse(record.initialState.finalizedAt),
        );
        if (
          record.receipt.attemptId === canonicalReplay.attemptId &&
          record.receipt.materialDigest ===
            firstUserBootstrapMaterialDigest(canonicalReplay)
        ) {
          return cloneBootstrapValue(record.receipt);
        }
        throw new FirstUserBootstrapConflictError(
          'Bootstrap finalization conflicts with the immutable completion receipt',
        );
      }

      const initialState = canonicalizeFirstUserBootstrapFinalization(
        record.claim,
        payload,
      );
      if ((await this.getAllUsersUnlocked()).length > 0) {
        throw new FirstUserBootstrapConflictError(
          'First-user bootstrap requires an empty user store',
        );
      }

      const completed: CompletedFirstUserBootstrapRecord = {
        version: 1,
        status: 'completed',
        tenantId: initialState.tenantId,
        claim: record.claim,
        receipt: createFirstUserBootstrapReceipt(record.claim, initialState),
        initialState,
      };
      await this.writeJsonFileAtomic(
        this.getFirstUserBootstrapPath(initialState.tenantId),
        completed,
      );
      return cloneBootstrapValue(completed.receipt);
    });
  }

  async getFirstUserBootstrapReceipt(
    tenantId: string,
  ): Promise<FirstUserBootstrapReceipt | null> {
    const record = await this.readFirstUserBootstrapRecord(
      normalizeFirstUserBootstrapTenantId(tenantId),
    );
    return record?.status === 'completed'
      ? cloneBootstrapValue(record.receipt)
      : null;
  }

  
  
  

  async getUser(id: string): Promise<AdminUser | null> {
    const users = await this.getAllUsers();
    return users.find(u => u.id === id) || null;
  }

  async getUserByHandle(handle: string): Promise<AdminUser | null> {
    const users = await this.getAllUsers();
    return users.find(u => u.handle === handle) || null;
  }

  async getUserByEmail(email: string): Promise<AdminUser | null> {
    const users = await this.getAllUsers();
    return users.find(u => u.email === email) || null;
  }

  async createUser(userData: Omit<AdminUser, 'id'>): Promise<AdminUser> {
    return this.withFirstUserBootstrapLock(async () => {
      const records = await this.getAllFirstUserBootstrapRecords();
      if (records.some((record) => record.status === 'claimed')) {
        throw new FirstUserBootstrapConflictError(
          'Cannot create a user while a first-user bootstrap claim is active',
        );
      }
      const completedRecords = records.filter(
        (record) => record.status === 'completed',
      );
      const users = await this.readCurrentUsers();
      const legacyReconciliation =
        await this.readLegacyFirstUserBootstrapReconciliation();
      if (completedRecords.length === 1) {
        if (legacyReconciliation) {
          throw new FirstUserBootstrapConflictError(
            'File storage contains conflicting bootstrap and legacy ownership records',
          );
        }
      } else if (completedRecords.length === 0 && users.length > 0) {
        await this.ensureLegacyFirstUserBootstrapReconciliation(users);
      } else {
        throw new FirstUserBootstrapConflictError(
          'Ordinary user creation requires a finalized first-user bootstrap receipt',
        );
      }
      const user: AdminUser = {
        id: randomUUID(),
        ...userData,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      users.push(user);
      await this.writeJsonFileAtomic(this.getPath('admin-users.json'), users);
      return user;
    });
  }

  async updateUser(id: string, updates: Partial<AdminUser>): Promise<AdminUser> {
    return this.withFirstUserBootstrapLock(async () => {
      const allUsers = await this.getAllUsersUnlocked();
      const current = allUsers.find((user) => user.id === id);
      if (!current) {
        throw new Error(`User not found: ${id}`);
      }

      const updated: AdminUser = {
        ...current,
        ...updates,
        id,
        updatedAt: new Date().toISOString(),
      };
      const storedUsers = await this.readCurrentUsers();
      const index = storedUsers.findIndex((user) => user.id === id);
      if (index === -1) storedUsers.push(updated);
      else storedUsers[index] = updated;
      await this.writeJsonFileAtomic(this.getPath('admin-users.json'), storedUsers);
      return updated;
    });
  }

  async deleteUser(id: string): Promise<boolean> {
    return this.withFirstUserBootstrapLock(async () => {
      const legacyReconciliation =
        await this.readLegacyFirstUserBootstrapReconciliation();
      if (legacyReconciliation?.owner.id === id) {
        throw new FirstUserBootstrapConflictError(
          'Cannot delete a legacy-reconciled first-user owner',
        );
      }
      const bootstrapRecord = await this.getBootstrapRecordForActor(id);
      if (bootstrapRecord) {
        throw new FirstUserBootstrapConflictError(
          bootstrapRecord.status === 'completed'
            ? 'Cannot delete a bootstrap-finalized actor'
            : 'Cannot delete a claimed first-user actor',
        );
      }

      const users = await this.readCurrentUsers();
      const index = users.findIndex((user) => user.id === id);
      if (index === -1) return false;
      const user = users[index];
      const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);

      users[index] = {
        ...user,
        isActive: false,
        updatedAt: new Date().toISOString(),
      };
      await this.writeJsonFileAtomic(this.getPath('admin-users.json'), users);
      await this.writeJsonFileAtomic(
        this.getPath('sessions.json'),
        sessions.filter((session) => session.userId !== id),
      );
      await this.removeFileIfExists(this.getTotpPath(user.handle));
      await this.removeFileIfExists(this.getBackupCodesPath(id));
      users.splice(index, 1);
      await this.writeJsonFileAtomic(this.getPath('admin-users.json'), users);
      return true;
    });
  }

  async getAllUsers(): Promise<AdminUser[]> {
    return this.getAllUsersUnlocked();
  }

  
  
  

  async getSession(id: string): Promise<Session | null> {
    const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
    return sessions.find(s => s.id === id) || null;
  }

  async createSession(
    userId: string,
    userData: Partial<AdminUser>,
    metadata?: SessionMetadata
  ): Promise<Session> {
    return this.withFirstUserBootstrapLock(async () => {
      if (userData.id !== undefined && userData.id !== userId) {
        throw new FirstUserBootstrapConflictError(
          'Session user identity does not match userId',
        );
      }
      const hasActiveBootstrapClaim = (await this.getAllFirstUserBootstrapRecords())
        .some((record) => record.status === 'claimed');
      if (hasActiveBootstrapClaim) {
        throw new FirstUserBootstrapConflictError(
          'session authority is unavailable while first-user bootstrap is claimed',
        );
      }
      const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
      const now = new Date();
      const expires = new Date(now.getTime() + this.config.sessionMaxAge);

      const session: Session = {
        id: randomBytes(32).toString('hex'),
        userId,
        expires: expires.toISOString(),
        expiresAt: expires.toISOString(),
        createdAt: now.toISOString(),
        user: userData.id ? {
          id: userData.id,
          username: userData.handle || '',
          name: userData.displayName || userData.handle || '',
          role: userData.role || 'viewer',
          needsOnboarding: userData.needsOnboarding,
          onboardingStep: userData.onboardingStep,
        } : undefined,
        clientIp: metadata?.clientIp || '',
        clientIpMasked: metadata?.clientIpMasked,
        userAgent: metadata?.userAgent || '',
        deviceType: metadata?.deviceType,
        browserFingerprint: metadata?.browserFingerprint,
        geoLocation: metadata?.geoLocation,
      };

      sessions.push(session);
      await this.writeJsonFileAtomic(this.getPath('sessions.json'), sessions);
      return session;
    });
  }

  async updateSession(id: string, updates: Partial<Session>): Promise<Session> {
    return this.withFirstUserBootstrapLock(async () => {
      const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
      const index = sessions.findIndex(s => s.id === id);

      if (index === -1) {
        throw new Error(`Session not found: ${id}`);
      }
      const current = sessions[index];
      if (updates.userId !== undefined && updates.userId !== current.userId) {
        throw new FirstUserBootstrapConflictError(
          'Session user identity is immutable',
        );
      }
      const currentNestedUserId = current.user?.id ?? current.userId;
      if (
        updates.user?.id !== undefined &&
        updates.user.id !== currentNestedUserId
      ) {
        throw new FirstUserBootstrapConflictError(
          'Nested session user identity is immutable',
        );
      }

      const updated = {
        ...current,
        ...cloneBootstrapValue(updates),
        id: current.id,
        userId: current.userId,
      };
      sessions[index] = updated;
      await this.writeJsonFileAtomic(this.getPath('sessions.json'), sessions);
      return cloneBootstrapValue(updated);
    });
  }

  async deleteSession(id: string): Promise<boolean> {
    return this.withFirstUserBootstrapLock(async () => {
      const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
      const index = sessions.findIndex(s => s.id === id);

      if (index === -1) return false;

      sessions.splice(index, 1);
      await this.writeJsonFileAtomic(this.getPath('sessions.json'), sessions);
      return true;
    });
  }

  async deleteUserSessions(userId: string): Promise<number> {
    return this.withFirstUserBootstrapLock(async () => {
      const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
      const before = sessions.length;
      const filtered = sessions.filter(s => s.userId !== userId);
      await this.writeJsonFileAtomic(this.getPath('sessions.json'), filtered);
      return before - filtered.length;
    });
  }

  async getSessionsByUser(userId: string): Promise<Session[]> {
    const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
    return sessions.filter(s => s.userId === userId);
  }

  async cleanupExpiredSessions(): Promise<number> {
    return this.withFirstUserBootstrapLock(async () => {
      const sessions = await this.readJsonFile<Session[]>(this.getPath('sessions.json'), []);
      const now = new Date();
      const before = sessions.length;
      const filtered = sessions.filter(s => new Date(s.expires) > now);
      await this.writeJsonFileAtomic(this.getPath('sessions.json'), filtered);
      return before - filtered.length;
    });
  }

  
  
  

  async getTOTPSecret(handle: string): Promise<EncryptedTOTPSecret | null> {
    const current = await this.readOptionalJsonFile<EncryptedTOTPSecret>(
      this.getTotpPath(handle),
    );
    if (current.exists) return current.value;
    for (const record of await this.getAllFirstUserBootstrapRecords()) {
      if (
        record.status === 'completed' &&
        record.initialState.totpSecret.handle.toLowerCase() === handle.toLowerCase()
      ) {
        return cloneBootstrapValue(record.initialState.totpSecret);
      }
    }
    return null;
  }

  async saveTOTPSecret(handle: string, secret: EncryptedTOTPSecret): Promise<void> {
    await this.withFirstUserBootstrapLock(async () => {
      const record = await this.getBootstrapRecordForActor(secret.userId, handle);
      if (record?.status === 'claimed') {
        throw new FirstUserBootstrapConflictError(
          'Cannot enroll TOTP for a claimed actor before finalization',
        );
      }
      await this.writeJsonFileAtomic(this.getTotpPath(handle), secret);
    });
  }

  async deleteTOTPSecret(handle: string): Promise<boolean> {
    return this.withFirstUserBootstrapLock(async () => {
      const bootstrapRecord = await this.getBootstrapRecordForActor(undefined, handle);
      if (bootstrapRecord) {
        throw new FirstUserBootstrapConflictError(
          'Cannot delete a claimed or bootstrap-finalized TOTP factor',
        );
      }
      return this.removeFileIfExists(this.getTotpPath(handle));
    });
  }

  
  
  

  async getBackupCodes(userId: string): Promise<BackupCodeSet | null> {
    const current = await this.readOptionalJsonFile<BackupCodeSet>(
      this.getBackupCodesPath(userId),
    );
    if (current.exists) return current.value;
    for (const record of await this.getAllFirstUserBootstrapRecords()) {
      if (
        record.status === 'completed' &&
        record.initialState.backupCodes.userId === userId
      ) {
        return cloneBootstrapValue(record.initialState.backupCodes);
      }
    }
    return null;
  }

  async saveBackupCodes(userId: string, codeSet: BackupCodeSet): Promise<void> {
    await this.withFirstUserBootstrapLock(async () => {
      const record = await this.getBootstrapRecordForActor(userId);
      if (record?.status === 'claimed') {
        throw new FirstUserBootstrapConflictError(
          'Cannot save backup codes for a claimed actor before finalization',
        );
      }
      await this.writeJsonFileAtomic(this.getBackupCodesPath(userId), codeSet);
    });
  }

  async deleteBackupCodes(userId: string): Promise<boolean> {
    return this.withFirstUserBootstrapLock(async () => {
      const bootstrapRecord = await this.getBootstrapRecordForActor(userId);
      if (bootstrapRecord) {
        throw new FirstUserBootstrapConflictError(
          'Cannot delete claimed or bootstrap-finalized backup codes',
        );
      }
      return this.removeFileIfExists(this.getBackupCodesPath(userId));
    });
  }

  
  
  

  async getInvitation(token: string): Promise<AdminInvitation | null> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    return invites.find(i => i.token === token) || null;
  }

  async getInvitationById(id: string): Promise<AdminInvitation | null> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    return invites.find(i => i.id === id) || null;
  }

  async createInvitation(data: Omit<AdminInvitation, 'id'>): Promise<AdminInvitation> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);

    const invitation: AdminInvitation = {
      id: randomUUID(),
      ...data,
    };

    invites.push(invitation);
    await this.writeJsonFile(this.getPath('invites.json'), invites);
    return invitation;
  }

  async updateInvitation(token: string, updates: Partial<AdminInvitation>): Promise<AdminInvitation> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    const index = invites.findIndex(i => i.token === token);

    if (index === -1) {
      throw new Error(`Invitation not found: ${token}`);
    }

    invites[index] = { ...invites[index], ...updates };
    await this.writeJsonFile(this.getPath('invites.json'), invites);
    return invites[index];
  }

  async deleteInvitation(token: string): Promise<boolean> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    const index = invites.findIndex(i => i.token === token);

    if (index === -1) return false;

    invites.splice(index, 1);
    await this.writeJsonFile(this.getPath('invites.json'), invites);
    return true;
  }

  async getPendingInvitations(): Promise<AdminInvitation[]> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    const now = new Date();
    return invites.filter(i => new Date(i.expiresAt) > now && !i.usedAt && i.isActive);
  }

  async getAllInvitations(): Promise<AdminInvitation[]> {
    return this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
  }

  async cleanupExpiredInvitations(): Promise<number> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    const now = new Date();
    const before = invites.length;
    const filtered = invites.filter(i =>
      new Date(i.expiresAt) > now || i.usedAt
    );
    await this.writeJsonFile(this.getPath('invites.json'), filtered);
    return before - filtered.length;
  }

  
  
  

  async logAuditEvent(event: Omit<AuditEvent, 'id'>): Promise<AuditEvent> {
    const logPath = this.getPath('logs/audit.json');
    const events = await this.readJsonFile<AuditEvent[]>(logPath, []);

    const auditEvent: AuditEvent = {
      id: randomUUID(),
      ...event,
    };

    events.push(auditEvent);

    
    if (events.length > 10000) {
      events.splice(0, events.length - 10000);
    }

    await this.writeJsonFile(logPath, events);
    return auditEvent;
  }

  async getAuditEvents(filters: AuditEventFilters): Promise<AuditEvent[]> {
    const logPath = this.getPath('logs/audit.json');
    let events = await this.readJsonFile<AuditEvent[]>(logPath, []);

    if (filters.type) {
      events = events.filter(e => e.type === filters.type);
    }

    if (filters.userId) {
      events = events.filter(e => e.userId === filters.userId || e.targetUserId === filters.userId);
    }

    if (filters.severity) {
      events = events.filter(e => e.severity === filters.severity);
    }

    if (filters.startDate) {
      const start = filters.startDate.getTime();
      events = events.filter(e => new Date(e.timestamp).getTime() >= start);
    }

    if (filters.endDate) {
      const end = filters.endDate.getTime();
      events = events.filter(e => new Date(e.timestamp).getTime() <= end);
    }

    const limit = filters.limit || 100;
    const offset = filters.offset || 0;

    return events.slice(offset, offset + limit);
  }

  async getRecentAuditEvents(limit: number = 100): Promise<AuditEvent[]> {
    const logPath = this.getPath('logs/audit.json');
    const events = await this.readJsonFile<AuditEvent[]>(logPath, []);
    return events.slice(-limit).reverse();
  }
}




export function createFileStorageAdapter(config?: Partial<FileStorageConfig>): FileStorageAdapter {
  return new FileStorageAdapter(config);
}
