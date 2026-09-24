import { constants, promises as fs } from 'node:fs';
import { createHmac, timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { ADMIN_ROLES } from '../types/auth.js';
import type { AdminUser, BackupCodeSet, EncryptedTOTPSecret, Session } from '../types/auth.js';
import {
  retirementMaterialDigest, totpRetirementFactorGeneration,
  totpRetirementFactorSnapshotDigest, totpRetirementRecoverySetDigest,
} from './totp-retirement-material.js';

/** Additive file capability. Generic, PG and Redis adapters are unchanged. */
export interface TotpRetirementStorage {
  getAllUsers(): Promise<AdminUser[]>;
  getSession(id: string): Promise<Session | null>;
  getTOTPSecret(handle: string): Promise<EncryptedTOTPSecret | null>;
  getBackupCodes(userId: string): Promise<BackupCodeSet | null>;
  getSessionsByUser(userId: string): Promise<Session[]>;
  deleteUserSessions(userId: string): Promise<number>;
  /** Compare exact validated material, unlink, and fsync parent even on replayed absence. */
  deleteTOTPSecretExpected(handle: string, expectedDigest: string): Promise<void>;
  deleteBackupCodesExpected(userId: string, expectedDigest: string | null): Promise<void>;
  /** Only false/absent factor flags; durably rewrite even after uncertain earlier ACK. */
  clearTotpFlagsExpected(userId: string, handle: string): Promise<void>;
}
export interface TotpRetirementBinding { userId: string; handle: string; sessionId: string }
export interface TotpRetirementAuthorizationContext {
  user: AdminUser;
  session: Session;
  factorGeneration: string;
  recoverySetDigest: string | null;
}
export interface TotpRetirementConsumedAuthorization {
  kind: 'consumed'; receiptId: string; actorId: string; action: 'factor.disable';
  resourceId: string; factorBinding: string;
}
export type TotpRetirementAuthorization<T> = TotpRetirementConsumedAuthorization | { kind: 'not-consumed'; result: T };
export interface TotpRetirementReceipt {
  version: 1; operationId: string; userId: string; handle: string; factorGeneration: string;
  committedAt: string; appliedAt: string;
}
export type TotpRetirementResult<T> = { kind: 'retired'; receipt: TotpRetirementReceipt } | { kind: 'not-consumed'; result: T };
export interface FileTotpRetirementConfig {
  directory: string;
  storage: TotpRetirementStorage;
  /** Existing reentrant enrollment gate, NOT a wrapper that calls this recover(). */
  withExclusiveAuth: <T>(operation: () => Promise<T>) => Promise<T>;
  signingKey: () => string;
  now?: () => number;
}
export class TotpRetirementError extends Error {
  constructor(readonly code: 'INVALID' | 'UNAUTHORIZED' | 'CONFLICT' | 'RECOVERY_REQUIRED', message: string) {
    super(message); this.name = 'TotpRetirementError';
  }
}
interface Committed {
  version: 1; state: 'committed'; operationId: string; userId: string; handle: string;
  factorGeneration: string; factorSnapshotDigest: string; recoverySetDigest: string | null;
  authorizationDigest: string; factorBinding: string; committedAt: string;
}
interface Applied { version: 1; state: 'applied'; authorizationDigest: string; receipt: TotpRetirementReceipt }
type RetirementRecord = Committed | Applied;
const HEX = /^[a-f0-9]{64}$/;
const REF = /^[A-Za-z0-9_-]{43}$/;
const MAX_RECORDS = 4096;
const MAX_BYTES = 8192;
const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
function fail(code: TotpRetirementError['code'] = 'INVALID'): never {
  throw new TotpRetirementError(code, 'Factor retirement requires current authority and durable storage');
}
function keys(value: unknown, required: readonly string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join('\0') !== [...required].sort().join('\0')) fail();
}
function text(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !value || value.length > 256 || value.includes('\0')) fail();
}
function component(value: unknown): asserts value is string {
  text(value);
  if (!/^[A-Za-z0-9_-]+$/.test(value)) fail();
}
function digest(value: unknown): asserts value is string { if (typeof value !== 'string' || !HEX.test(value)) fail(); }
function stamp(value: unknown): asserts value is string { text(value); if (!Number.isFinite(Date.parse(value))) fail(); }
function receipt(value: unknown): asserts value is TotpRetirementReceipt {
  keys(value, ['version', 'operationId', 'userId', 'handle', 'factorGeneration', 'committedAt', 'appliedAt']);
  if (value.version !== 1) fail();
  digest(value.operationId); component(value.userId); component(value.handle); digest(value.factorGeneration);
  stamp(value.committedAt); stamp(value.appliedAt);
  if (Date.parse(value.appliedAt) < Date.parse(value.committedAt)) fail();
}
function record(value: unknown): asserts value is RetirementRecord {
  if (!value || typeof value !== 'object' || !('state' in value)) fail();
  const fields = value as Record<string, unknown>;
  if (fields.state === 'applied') {
    keys(fields, ['version', 'state', 'authorizationDigest', 'receipt']);
    if (fields.version !== 1) fail();
    digest(fields.authorizationDigest); receipt(fields.receipt);
  } else {
    keys(fields, ['version', 'state', 'operationId', 'userId', 'handle', 'factorGeneration', 'factorSnapshotDigest',
      'recoverySetDigest', 'authorizationDigest', 'factorBinding', 'committedAt']);
    if (fields.version !== 1 || fields.state !== 'committed') fail();
    component(fields.userId); component(fields.handle); stamp(fields.committedAt);
    for (const field of ['operationId', 'factorGeneration', 'factorSnapshotDigest', 'authorizationDigest', 'factorBinding']) digest(fields[field]);
    if (fields.recoverySetDigest !== null) digest(fields.recoverySetDigest);
  }
}
function authorization(value: unknown, binding: TotpRetirementBinding): asserts value is TotpRetirementConsumedAuthorization {
  keys(value, ['kind', 'receiptId', 'actorId', 'action', 'resourceId', 'factorBinding']);
  if (value.kind !== 'consumed' || value.action !== 'factor.disable' || value.actorId !== binding.userId ||
      value.resourceId !== binding.userId || typeof value.receiptId !== 'string' || !REF.test(value.receiptId)) fail('UNAUTHORIZED');
  digest(value.factorBinding);
}
function flags(user: AdminUser, handle: string): void {
  if (!((user.totpEnabled === true && user.totpSecretId === handle) ||
      (user.totpEnabled === false && !user.totpSecretId))) fail('CONFLICT');
}
function principalDigest(user: AdminUser): string {
  // Mutable audit timestamps are not authority; credentials, grants and lifecycle are.
  const data = user as unknown as Record<string, unknown>;
  return retirementMaterialDigest('principal', Object.fromEntries([
    'id', 'handle', 'passwordHash', 'githubId', 'githubLogin', 'githubLinkedAt', 'role', 'permissions',
    'isActive', 'isLocked', 'needsOnboarding', 'firstLogin', 'removedAt', 'removedBy', 'totpEnabled', 'totpSecretId',
  ].map(key => [key, data[key] ?? null])));
}

/** Single-writer restart recovery; no cross-process CAS or application policy defaults. */
export class FileTotpRetirementCoordinator {
  private readonly directory: string;
  constructor(private readonly config: FileTotpRetirementConfig) {
    if (!config.directory || typeof config.withExclusiveAuth !== 'function') fail();
    this.directory = path.resolve(config.directory);
  }
  async recover(): Promise<void> {
    return this.config.withExclusiveAuth(() => this.recoverUnsafe());
  }
  async retire<T>(input: TotpRetirementBinding & {
    /** Trusted app callback must consume real action-bound proof and compare its live factorBinding. */
    authorize: (current: TotpRetirementAuthorizationContext) => Promise<TotpRetirementAuthorization<T>>;
  }): Promise<TotpRetirementResult<T>> {
    const binding = { userId: input.userId, handle: input.handle, sessionId: input.sessionId };
    component(binding.userId); component(binding.handle); text(binding.sessionId);
    if (typeof input.authorize !== 'function') fail('UNAUTHORIZED');
    return this.config.withExclusiveAuth(async () => {
      await this.recoverUnsafe();
      const before = await this.current(binding);
      const decision = await input.authorize(copy(before.context));
      if (decision && decision.kind === 'not-consumed') {
        keys(decision, ['kind', 'result']);
        return { kind: 'not-consumed', result: decision.result };
      }
      authorization(decision, binding);
      const after = await this.current(binding);
      if (principalDigest(before.context.user) !== principalDigest(after.context.user) ||
          before.context.session.createdAt !== after.context.session.createdAt ||
          before.context.factorGeneration !== after.context.factorGeneration ||
          before.context.recoverySetDigest !== after.context.recoverySetDigest ||
          (after.factor.lastUsedTotpStep ?? -1) < (before.factor.lastUsedTotpStep ?? -1) ||
          (before.factor.lastUsedAt && (!after.factor.lastUsedAt || Date.parse(after.factor.lastUsedAt) < Date.parse(before.factor.lastUsedAt)))) fail('CONFLICT');
      const authorizationDigest = this.mac('authorization', decision.receiptId);
      const operationId = this.mac('operation', decision.receiptId);
      // Never reinterpret a consumed receipt as permission to retire a later generation.
      if (await this.read(operationId)) fail('CONFLICT');
      if ((await this.filenames()).length >= MAX_RECORDS) fail('RECOVERY_REQUIRED');
      if (Date.parse(after.context.session.expires) <= Date.parse(this.now())) fail('UNAUTHORIZED');
      const committed: Committed = { version: 1, state: 'committed', operationId,
        userId: binding.userId, handle: binding.handle, authorizationDigest,
        factorBinding: decision.factorBinding, factorGeneration: after.context.factorGeneration,
        factorSnapshotDigest: totpRetirementFactorSnapshotDigest(after.factor),
        recoverySetDigest: after.context.recoverySetDigest, committedAt: this.now() };
      await this.write(committed);
      return { kind: 'retired', receipt: await this.apply(committed) };
    });
  }
  /** Trusted receipt lookup, not a session or HTTP authorization mechanism. Never reprojects applied state. */
  async readReceipt(input: { receiptId: string; userId: string }): Promise<TotpRetirementReceipt | null> {
    if (!REF.test(input.receiptId)) fail(); component(input.userId);
    return this.config.withExclusiveAuth(async () => {
      await this.recoverUnsafe();
      const value = await this.read(this.mac('operation', input.receiptId));
      if (!value || value.state !== 'applied' || value.receipt.userId !== input.userId ||
          value.authorizationDigest !== this.mac('authorization', input.receiptId)) return null;
      return copy(value.receipt);
    });
  }
  private async owner(userId: string, handle: string): Promise<AdminUser> {
    const users = await this.config.storage.getAllUsers();
    if (!Array.isArray(users)) fail('RECOVERY_REQUIRED');
    const matches = users.filter(user => user.id === userId || user.handle === handle);
    if (matches.length !== 1 || matches[0].id !== userId || matches[0].handle !== handle) fail('CONFLICT');
    return matches[0];
  }
  private async current(binding: TotpRetirementBinding) {
    const storage = this.config.storage;
    const user = await this.owner(binding.userId, binding.handle);
    if (user.isActive !== true || user.isLocked === true || user.needsOnboarding !== false || user.firstLogin === true ||
        Object.hasOwn(user, 'removedAt') || Object.hasOwn(user, 'removedBy') || !ADMIN_ROLES.includes(user.role) ||
        user.totpEnabled !== true || user.totpSecretId !== binding.handle) fail('UNAUTHORIZED');
    const factor = await storage.getTOTPSecret(binding.handle);
    const codes = await storage.getBackupCodes(binding.userId);
    if (!factor || factor.userId !== binding.userId || factor.handle !== binding.handle ||
        (codes && codes.userId !== binding.userId)) fail('CONFLICT');
    const factorGeneration = totpRetirementFactorGeneration(factor);
    const recoverySetDigest = totpRetirementRecoverySetDigest(codes);
    // Session is checked last, after credential I/O, immediately before authority returns.
    const session = await storage.getSession(binding.sessionId);
    if (!session || session.id !== binding.sessionId || session.userId !== binding.userId ||
        (session.user && session.user.id !== binding.userId) || session.user?.needsOnboarding === true ||
        !Number.isFinite(Date.parse(session.createdAt)) || Date.parse(session.createdAt) > Date.parse(this.now()) ||
        !Number.isFinite(Date.parse(session.expires)) || Date.parse(session.expires) <= Date.parse(this.now())) fail('UNAUTHORIZED');
    return { context: { user, session, factorGeneration, recoverySetDigest }, factor };
  }
  private async apply(value: Committed): Promise<TotpRetirementReceipt> {
    try {
      const storage = this.config.storage;
      const user = await this.owner(value.userId, value.handle); flags(user, value.handle);
      const factor = await storage.getTOTPSecret(value.handle);
      const codes = await storage.getBackupCodes(value.userId);
      if ((factor && (factor.userId !== value.userId || factor.handle !== value.handle ||
          totpRetirementFactorGeneration(factor) !== value.factorGeneration ||
          totpRetirementFactorSnapshotDigest(factor) !== value.factorSnapshotDigest)) ||
          (codes && (codes.userId !== value.userId || totpRetirementRecoverySetDigest(codes) !== value.recoverySetDigest))) fail('CONFLICT');
      // Re-acknowledge revocation on every replay before weakening credentials or flags.
      await storage.deleteUserSessions(value.userId);
      if ((await storage.getSessionsByUser(value.userId)).length !== 0) fail('RECOVERY_REQUIRED');
      await storage.deleteTOTPSecretExpected(value.handle, value.factorSnapshotDigest);
      await storage.deleteBackupCodesExpected(value.userId, value.recoverySetDigest);
      await storage.clearTotpFlagsExpected(value.userId, value.handle);
      if (await storage.getTOTPSecret(value.handle) || await storage.getBackupCodes(value.userId) ||
          (await storage.getSessionsByUser(value.userId)).length !== 0) fail('RECOVERY_REQUIRED');
      const after = await this.owner(value.userId, value.handle);
      if (after.totpEnabled !== false || after.totpSecretId) fail('RECOVERY_REQUIRED');
      const result: TotpRetirementReceipt = { version: 1, operationId: value.operationId, userId: value.userId,
        handle: value.handle, factorGeneration: value.factorGeneration, committedAt: value.committedAt, appliedAt: this.now() };
      receipt(result);
      await this.write({ version: 1, state: 'applied', authorizationDigest: value.authorizationDigest, receipt: result });
      return copy(result);
    } catch { fail('RECOVERY_REQUIRED'); }
  }
  private async recoverUnsafe(): Promise<void> {
    await this.prepare();
    for (const name of await this.filenames()) {
      const value = await this.read(name.slice(0, -5));
      if (!value) fail('RECOVERY_REQUIRED');
      if (value.state === 'committed') await this.apply(value);
    }
  }
  private now(): string {
    const now = (this.config.now ?? Date.now)();
    if (!Number.isSafeInteger(now) || !Number.isFinite(new Date(now).getTime())) fail('RECOVERY_REQUIRED');
    return new Date(now).toISOString();
  }
  private mac(domain: string, value: string): string {
    const key = this.config.signingKey();
    if (typeof key !== 'string' || Buffer.byteLength(key) < 32) fail('RECOVERY_REQUIRED');
    return createHmac('sha256', key).update(`tinyland-auth:totp-retirement:${domain}:v1\0`).update(value).digest('hex');
  }
  private async syncDirectory(): Promise<void> {
    const handle = await fs.open(this.directory, 'r');
    try { await handle.sync(); } finally { await handle.close(); }
  }
  private async prepare(): Promise<void> {
    try {
      let ancestor = path.parse(this.directory).root;
      const parentPath = path.dirname(this.directory);
      for (const part of path.relative(ancestor, parentPath).split(path.sep).filter(Boolean)) {
        const next = path.join(ancestor, part);
        const stat = await fs.lstat(next);
        if (!stat.isDirectory() || stat.isSymbolicLink()) fail();
        ancestor = next;
      }
      // The enclosing auth root already belongs to the existing enrollment gate.
      try { await fs.mkdir(this.directory, { mode: 0o700 }); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
      const stat = await fs.lstat(this.directory);
      if (!stat.isDirectory() || stat.isSymbolicLink()) fail();
      const parent = await fs.open(parentPath, 'r');
      try { await parent.sync(); } finally { await parent.close(); }
      await fs.chmod(this.directory, 0o700);
      // A prior rename's failed ACK cannot be read before its durability is acknowledged.
      await this.syncDirectory();
    } catch { fail('RECOVERY_REQUIRED'); }
  }
  private async filenames(): Promise<string[]> {
    const names: string[] = [];
    const dir = await fs.opendir(this.directory);
    let total = 0;
    for await (const item of dir) {
      if (++total > MAX_RECORDS * 2) fail('RECOVERY_REQUIRED');
      if (/^[a-f0-9]{64}\.json\.[a-f0-9]{24}\.tmp$/.test(item.name) && item.isFile()) continue;
      if (!/^[a-f0-9]{64}\.json$/.test(item.name) || !item.isFile() || names.length >= MAX_RECORDS) fail('RECOVERY_REQUIRED');
      names.push(item.name);
    }
    return names.sort();
  }
  private async read(operationId: string): Promise<RetirementRecord | null> {
    digest(operationId);
    let handle;
    try { handle = await fs.open(path.join(this.directory, `${operationId}.json`), constants.O_RDONLY | constants.O_NOFOLLOW); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; fail('RECOVERY_REQUIRED'); }
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_BYTES || stat.size <= 0) fail();
      const raw = await handle.readFile('utf8');
      if (Buffer.byteLength(raw) > MAX_BYTES) fail();
      const envelope: unknown = JSON.parse(raw);
      keys(envelope, ['version', 'record', 'seal']);
      if (envelope.version !== 1) fail(); record(envelope.record); digest(envelope.seal);
      if (!timingSafeEqual(Buffer.from(envelope.seal, 'hex'), Buffer.from(this.mac('seal', JSON.stringify(envelope.record)), 'hex'))) fail();
      const storedId = envelope.record.state === 'committed' ? envelope.record.operationId : envelope.record.receipt.operationId;
      if (storedId !== operationId) fail();
      return envelope.record;
    } catch { fail('RECOVERY_REQUIRED'); } finally { await handle.close(); }
  }
  private async write(value: RetirementRecord): Promise<void> {
    record(value);
    const id = value.state === 'committed' ? value.operationId : value.receipt.operationId;
    const filename = path.join(this.directory, `${id}.json`);
    const temporary = `${filename}.${randomBytes(12).toString('hex')}.tmp`;
    const body = JSON.stringify({ version: 1, record: value, seal: this.mac('seal', JSON.stringify(value)) });
    if (Buffer.byteLength(body) > MAX_BYTES) fail();
    try {
      const handle = await fs.open(temporary, 'wx', 0o600);
      try { await handle.writeFile(body); await handle.sync(); } finally { await handle.close(); }
      await fs.rename(temporary, filename);
      await this.syncDirectory();
    } catch { await fs.unlink(temporary).catch(() => undefined); fail('RECOVERY_REQUIRED'); }
  }
}
