import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { createBackupCodeSet, generateBackupCodes, hashBackupCode } from '../core/backup-codes/index.js';
import type { TOTPService } from '../core/totp/index.js';
import { ADMIN_ROLES } from '../types/auth.js';
import type { AdminUser, BackupCodeSet, EncryptedData, EncryptedTOTPSecret, Session } from '../types/auth.js';

export interface TotpEnrollmentBinding {
  userId: string;
  sessionId: string;
}

export interface TotpEnrollmentCurrentState {
  user: AdminUser | null;
  session: Session | null;
  totpSecret: EncryptedTOTPSecret | null;
  backupCodes: BackupCodeSet | null;
}

/** Returned only to the authenticated setup page, never stored in a cookie. */
export interface TotpEnrollmentSetup {
  attemptId: string;
  expiresAt: string;
  secret: string;
  qrCodeUrl: string;
  backupCodes: string[];
}

export interface TotpEnrollmentUserPatch {
  totpEnabled: true;
  totpSecretId: string;
  needsOnboarding: true;
  onboardingStep: number;
}

/** Frozen projection input. It deliberately cannot activate a user or change a role. */
export interface TotpEnrollmentCompletion {
  version: 1;
  attemptId: string;
  userId: string;
  handle: string;
  sessionDigest: string;
  completedAt: string;
  totpSecret: EncryptedTOTPSecret;
  backupCodes: BackupCodeSet;
  userPatch: TotpEnrollmentUserPatch;
}

export interface TotpEnrollmentReceipt {
  version: 1;
  attemptId: string;
  userId: string;
  handle: string;
  completedAt: string;
  materialDigest: string;
}

export interface FileTotpEnrollmentConfig {
  /** Private, durable directory; one application process owns this storage root. */
  directory: string;
  totp: Pick<TOTPService, 'generateSecret' | 'generateQRCode' | 'encrypt' | 'decrypt' | 'verifyTokenWithStep'>;
  /** Uncached canonical reads. Must not re-enter this coordinator's gate. */
  loadCurrent(binding: TotpEnrollmentBinding): Promise<TotpEnrollmentCurrentState>;
  /**
   * Idempotently and durably write factor, backup hashes and ONLY userPatch,
   * in that order. Preserve a greater existing onboarding step.
   * Use raw underlying adapters, not gated entrypoints. Never refresh sessions
   * here. A thrown error keeps all guarded auth traffic closed until recovery.
   */
  project(completion: TotpEnrollmentCompletion): Promise<void>;
  /** Positive and at most ten minutes. Does not extend an existing attempt. */
  ttlMs?: number;
  now?: () => Date;
}

export class TotpEnrollmentError extends Error {
  constructor(readonly code: 'INVALID' | 'CONFLICT' | 'EXPIRED' | 'UNAUTHORIZED' | 'RECOVERY_REQUIRED', message: string) {
    super(message);
    this.name = 'TotpEnrollmentError';
  }
}

interface PendingRecord {
  version: 1;
  state: 'pending';
  attemptId: string;
  userId: string;
  handle: string;
  sessionDigest: string;
  createdAt: string;
  expiresAt: string;
  secret: EncryptedData;
  recoveryCodes: EncryptedData;
  backupCodes: BackupCodeSet;
}

interface CommittedRecord {
  version: 1;
  state: 'committed';
  completion: TotpEnrollmentCompletion;
  receipt: TotpEnrollmentReceipt;
}

interface AppliedRecord {
  version: 1;
  state: 'applied';
  sessionDigest: string;
  receipt: TotpEnrollmentReceipt;
}

type EnrollmentRecord = PendingRecord | CommittedRecord | AppliedRecord;
interface GateState { projecting: boolean; recoveryRequired: boolean }
interface GateContext { active: boolean; state: GateState; tail: Promise<void> }
interface ProcessGate { tail: Promise<void>; context: AsyncLocalStorage<GateContext> }
const processGates = new Map<string, ProcessGate>();
const MAX_TTL_MS = 10 * 60 * 1000;
const HEX_DIGEST = /^[a-f0-9]{64}$/;
const ATTEMPT_ID = /^[a-f0-9]{48}$/;

function fail(message: string): never {
  throw new TotpEnrollmentError('INVALID', message);
}

function object(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('Invalid enrollment record');
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('Unexpected enrollment record fields');
  }
}

function text(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 8192 || value.includes('\0')) {
    fail('Invalid enrollment string');
  }
}

function timestamp(value: unknown): asserts value is string {
  text(value);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) fail('Invalid enrollment timestamp');
}

function digest(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !HEX_DIGEST.test(value)) fail('Invalid enrollment digest');
}

function attemptId(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !ATTEMPT_ID.test(value)) fail('Invalid enrollment attempt ID');
}

function encrypted(value: unknown): asserts value is EncryptedData {
  object(value, ['encrypted', 'salt', 'iv', 'tag']);
  for (const part of Object.values(value)) text(part);
}

function codes(value: unknown, userId: string): asserts value is BackupCodeSet {
  object(value, ['userId', 'codes', 'generatedAt']);
  if (value.userId !== userId || !Array.isArray(value.codes) || value.codes.length !== 10) fail('Invalid enrollment backup codes');
  timestamp(value.generatedAt);
  const ids = new Set<string>();
  const hashes = new Set<string>();
  for (const code of value.codes) {
    object(code, ['id', 'hash', 'used']);
    text(code.id);
    digest(code.hash);
    if (code.used !== false || ids.has(code.id) || hashes.has(code.hash)) fail('Invalid initial backup-code state');
    ids.add(code.id);
    hashes.add(code.hash);
  }
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function materialDigest(completion: TotpEnrollmentCompletion): string {
  return createHash('sha256').update('tinyland-auth:totp-enrollment:v1\0').update(canonical(completion)).digest('hex');
}

function sessionDigest(binding: TotpEnrollmentBinding): string {
  text(binding.userId);
  text(binding.sessionId);
  return createHash('sha256').update('tinyland-auth:enrollment-session:v1\0').update(JSON.stringify([binding.userId, binding.sessionId])).digest('hex');
}

function copy<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T; }

function validateReceipt(value: unknown): asserts value is TotpEnrollmentReceipt {
  object(value, ['version', 'attemptId', 'userId', 'handle', 'completedAt', 'materialDigest']);
  if (value.version !== 1) fail('Unsupported enrollment receipt');
  attemptId(value.attemptId);
  text(value.userId);
  text(value.handle);
  timestamp(value.completedAt);
  digest(value.materialDigest);
}

function validateCompletion(value: unknown): asserts value is TotpEnrollmentCompletion {
  object(value, ['version', 'attemptId', 'userId', 'handle', 'sessionDigest', 'completedAt', 'totpSecret', 'backupCodes', 'userPatch']);
  if (value.version !== 1) fail('Unsupported enrollment completion');
  attemptId(value.attemptId);
  text(value.userId);
  text(value.handle);
  digest(value.sessionDigest);
  timestamp(value.completedAt);
  codes(value.backupCodes, value.userId);
  object(value.totpSecret, ['userId', 'handle', 'encryptedSecret', 'iv', 'authTag', 'salt', 'createdAt', 'backupCodesGenerated', 'version', 'lastUsedAt', 'lastUsedTotpStep']);
  const factor = value.totpSecret;
  if (factor.userId !== value.userId || factor.handle !== value.handle || factor.version !== 1 || factor.backupCodesGenerated !== true || !Number.isSafeInteger(factor.lastUsedTotpStep) || (factor.lastUsedTotpStep as number) < 0) fail('Invalid enrollment factor binding');
  for (const key of ['encryptedSecret', 'iv', 'authTag', 'salt']) text(factor[key]);
  timestamp(factor.createdAt);
  if (factor.createdAt !== value.completedAt || factor.lastUsedAt !== value.completedAt) fail('Invalid enrollment factor timestamps');
  object(value.userPatch, ['totpEnabled', 'totpSecretId', 'needsOnboarding', 'onboardingStep']);
  if (value.userPatch.totpEnabled !== true || value.userPatch.totpSecretId !== value.handle || value.userPatch.needsOnboarding !== true || !Number.isSafeInteger(value.userPatch.onboardingStep) || (value.userPatch.onboardingStep as number) < 2 || (value.userPatch.onboardingStep as number) > 3) fail('Invalid enrollment user patch');
}

function parseRecord(value: unknown): EnrollmentRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('Invalid enrollment record');
  const record = value as Record<string, unknown>;
  if (record.version !== 1) fail('Unsupported enrollment record');
  if (record.state === 'pending') {
    object(record, ['version', 'state', 'attemptId', 'userId', 'handle', 'sessionDigest', 'createdAt', 'expiresAt', 'secret', 'recoveryCodes', 'backupCodes']);
    attemptId(record.attemptId);
    text(record.userId);
    text(record.handle);
    digest(record.sessionDigest);
    timestamp(record.createdAt);
    timestamp(record.expiresAt);
    const age = Date.parse(record.expiresAt) - Date.parse(record.createdAt);
    if (age <= 0 || age > MAX_TTL_MS) fail('Invalid enrollment expiry');
    encrypted(record.secret);
    encrypted(record.recoveryCodes);
    codes(record.backupCodes, record.userId);
  } else if (record.state === 'committed') {
    object(record, ['version', 'state', 'completion', 'receipt']);
    validateCompletion(record.completion);
    validateReceipt(record.receipt);
    const { completion, receipt } = record;
    if (receipt.attemptId !== completion.attemptId || receipt.userId !== completion.userId || receipt.handle !== completion.handle || receipt.completedAt !== completion.completedAt || receipt.materialDigest !== materialDigest(completion)) fail('Enrollment receipt does not match its material');
  } else if (record.state === 'applied') {
    object(record, ['version', 'state', 'sessionDigest', 'receipt']);
    digest(record.sessionDigest);
    validateReceipt(record.receipt);
  } else {
    fail('Unknown enrollment record state');
  }
  return record as unknown as EnrollmentRecord;
}

/**
 * Single-process, restart-durable onboarding enrollment. This is not a
 * cross-process lock or a distributed transaction. All participating auth
 * traffic/mutations must share withReadyAuth, including application projections.
 */
export class FileTotpEnrollmentCoordinator {
  private readonly directory: string;
  private readonly gate: ProcessGate;
  private readonly ttlMs: number;
  private readonly now: () => Date;

  constructor(private readonly config: FileTotpEnrollmentConfig) {
    if (!config.directory) fail('Enrollment directory is required');
    this.directory = path.resolve(config.directory);
    this.ttlMs = config.ttlMs ?? MAX_TTL_MS;
    if (!Number.isSafeInteger(this.ttlMs) || this.ttlMs <= 0 || this.ttlMs > MAX_TTL_MS) fail('Enrollment TTL must be at most ten minutes');
    this.now = config.now ?? (() => new Date());
    let gate = processGates.get(this.directory);
    if (!gate) {
      gate = { tail: Promise.resolve(), context: new AsyncLocalStorage<GateContext>() };
      processGates.set(this.directory, gate);
    }
    this.gate = gate;
  }

  /** Reentrant within a request. No callback runs while recovery is incomplete. */
  async withReadyAuth<T>(operation: () => Promise<T>): Promise<T> {
    const current = this.gate.context.getStore();
    if (current?.active) {
      if (current.state.projecting) throw new TotpEnrollmentError('RECOVERY_REQUIRED', 'Enrollment projections must use raw storage, not the auth gate');
      // A separate child context permits sequential reentry without letting
      // Promise.all siblings bypass serialization under the same request token.
      const result = current.tail.then(() => this.runContext(operation, current.state));
      current.tail = result.then(() => undefined, () => undefined);
      return result;
    }
    const result = this.gate.tail.then(() => this.runContext(operation, { projecting: false, recoveryRequired: true }));
    this.gate.tail = result.then(() => undefined, () => undefined);
    return result;
  }

  private runContext<T>(operation: () => Promise<T>, state: GateState): Promise<T> {
    const context: GateContext = { active: true, state, tail: Promise.resolve() };
    return this.gate.context.run(context, async () => {
      try {
        if (state.recoveryRequired) await this.recoverUnsafe();
        return await operation();
      } finally {
        // A callback inheriting this context may append a child while an older
        // tail is draining. Do not release the root gate until the tail is stable.
        for (;;) {
          const tail = context.tail;
          await tail;
          if (tail === context.tail) {
            context.active = false;
            break;
          }
        }
      }
    });
  }

  async recover(): Promise<void> {
    await this.withReadyAuth(async () => { await this.recoverUnsafe(); });
  }

  async begin(binding: TotpEnrollmentBinding): Promise<TotpEnrollmentSetup> {
    const bound = copy(binding);
    return this.withReadyAuth(async () => {
      const state = await this.current(bound, true);
      const existing = await this.readRecord(bound.userId);
      const now = this.now().toISOString();
      if (existing?.state === 'pending' && Date.parse(existing.expiresAt) > Date.parse(now)) {
        this.checkBinding(existing, bound, state.user!.handle);
        this.checkExpiry(existing);
        const setup = await this.setup(existing);
        const fresh = await this.current(bound, true);
        this.checkBinding(existing, bound, fresh.user!.handle);
        this.checkExpiry(existing);
        return setup;
      }
      const generated = await this.config.totp.generateSecret(state.user!.handle);
      const plaintextCodes = generateBackupCodes();
      const record: PendingRecord = {
        version: 1, state: 'pending', attemptId: randomBytes(24).toString('hex'),
        userId: bound.userId, handle: state.user!.handle, sessionDigest: sessionDigest(bound),
        createdAt: now, expiresAt: new Date(Date.parse(now) + this.ttlMs).toISOString(),
        secret: this.config.totp.encrypt(generated.secret),
        recoveryCodes: this.config.totp.encrypt(JSON.stringify(plaintextCodes)),
        backupCodes: { ...createBackupCodeSet(bound.userId, plaintextCodes), generatedAt: now },
      };
      // Validate ciphertext round trips before publishing any pending authority.
      const setup = await this.setup(record);
      const fresh = await this.current(bound, true);
      this.checkBinding(record, bound, fresh.user!.handle);
      if (this.now().getTime() >= Date.parse(record.expiresAt)) throw new TotpEnrollmentError('EXPIRED', 'Enrollment expired during setup');
      await this.writeRecord(record);
      return setup;
    });
  }

  async complete(input: TotpEnrollmentBinding & { attemptId: string; token: string }): Promise<TotpEnrollmentReceipt> {
    const bound = copy(input);
    attemptId(bound.attemptId);
    return this.withReadyAuth(async () => {
      const state = await this.current(bound, false);
      const record = await this.readRecord(bound.userId);
      if (!record) throw new TotpEnrollmentError('CONFLICT', 'Enrollment attempt does not exist');
      if (record.state === 'applied') {
        if (record.receipt.attemptId !== bound.attemptId || record.receipt.handle !== state.user!.handle || record.sessionDigest !== sessionDigest(bound)) throw new TotpEnrollmentError('CONFLICT', 'Enrollment receipt belongs to another attempt or session');
        // Never re-project a receipt: live codes/factors may have changed since.
        return copy(record.receipt);
      }
      if (record.state !== 'pending') throw new TotpEnrollmentError('RECOVERY_REQUIRED', 'Enrollment projection is incomplete');
      this.checkBinding(record, bound, state.user!.handle);
      if (record.attemptId !== bound.attemptId) throw new TotpEnrollmentError('CONFLICT', 'Enrollment attempt changed');
      this.checkExpiry(record);
      await this.current(bound, true);
      this.plainRecoveryCodes(record);
      if (typeof bound.token !== 'string' || !/^\d{6}$/.test(bound.token.replace(/\s/g, ''))) throw new TotpEnrollmentError('INVALID', 'Invalid TOTP code');
      const secret = this.config.totp.decrypt(record.secret);
      const verification = await this.config.totp.verifyTokenWithStep({ handle: record.handle, secret, createdAt: new Date(record.createdAt) }, bound.token);
      if (!verification.valid || !Number.isSafeInteger(verification.step) || verification.step! < 0) throw new TotpEnrollmentError('INVALID', 'Invalid TOTP code');
      this.checkExpiry(record);
      const fresh = await this.current(bound, true);
      this.checkBinding(record, bound, fresh.user!.handle);
      const ciphertext = this.config.totp.encrypt(secret);
      const roundTrip = Buffer.from(this.config.totp.decrypt(ciphertext));
      const original = Buffer.from(secret);
      if (roundTrip.length !== original.length || !timingSafeEqual(roundTrip, original)) fail('TOTP encryption round trip failed');
      const completedAt = this.now().toISOString();
      this.checkExpiry(record);
      const completion: TotpEnrollmentCompletion = {
        version: 1, attemptId: record.attemptId, userId: record.userId, handle: record.handle,
        sessionDigest: record.sessionDigest, completedAt,
        totpSecret: {
          userId: record.userId, handle: record.handle, encryptedSecret: ciphertext.encrypted,
          iv: ciphertext.iv, authTag: ciphertext.tag, salt: ciphertext.salt,
          createdAt: completedAt, backupCodesGenerated: true, version: 1,
          lastUsedAt: completedAt, lastUsedTotpStep: verification.step,
        },
        backupCodes: copy(record.backupCodes),
        userPatch: { totpEnabled: true, totpSecretId: record.handle, needsOnboarding: true, onboardingStep: Math.max(fresh.user!.onboardingStep, 2) },
      };
      const receipt: TotpEnrollmentReceipt = {
        version: 1, attemptId: record.attemptId, userId: record.userId, handle: record.handle,
        completedAt, materialDigest: materialDigest(completion),
      };
      const committed: CommittedRecord = { version: 1, state: 'committed', completion, receipt };
      // This replacement consumes the attempt. No projection precedes it.
      this.gate.context.getStore()!.state.recoveryRequired = true;
      await this.writeRecord(committed);
      await this.apply(committed);
      this.gate.context.getStore()!.state.recoveryRequired = false;
      return copy(receipt);
    });
  }

  private async current(binding: TotpEnrollmentBinding, requireUnenrolled: boolean): Promise<TotpEnrollmentCurrentState> {
    sessionDigest(binding);
    const current = await this.config.loadCurrent(copy(binding));
    const { user, session } = current;
    const expires = session ? Date.parse(session.expires) : NaN;
    if (!user || user.id !== binding.userId || user.isActive !== true || user.isLocked === true || !ADMIN_ROLES.includes(user.role) || !session || session.id !== binding.sessionId || session.userId !== binding.userId || (session.user && session.user.id !== binding.userId) || !Number.isFinite(expires) || expires <= this.now().getTime()) throw new TotpEnrollmentError('UNAUTHORIZED', 'A live current principal and bound session are required');
    text(user.handle);
    if (requireUnenrolled && (user.needsOnboarding !== true || !Number.isSafeInteger(user.onboardingStep) || user.onboardingStep < 1 || user.onboardingStep > 3 || user.totpEnabled !== false || Boolean(user.totpSecretId) || current.totpSecret !== null || current.backupCodes !== null)) throw new TotpEnrollmentError('CONFLICT', 'Enrollment requires a pending onboarded profile and no existing factor or backup codes');
    return current;
  }

  private checkBinding(record: PendingRecord, binding: TotpEnrollmentBinding, handle: string): void {
    if (record.userId !== binding.userId || record.handle !== handle || record.sessionDigest !== sessionDigest(binding)) throw new TotpEnrollmentError('CONFLICT', 'Enrollment belongs to another principal or session');
  }

  private checkExpiry(record: PendingRecord): void {
    const now = this.now().getTime();
    if (now < Date.parse(record.createdAt) || now >= Date.parse(record.expiresAt)) throw new TotpEnrollmentError('EXPIRED', 'Enrollment attempt expired');
  }

  private async setup(record: PendingRecord): Promise<TotpEnrollmentSetup> {
    parseRecord(record);
    const secret = this.config.totp.decrypt(record.secret);
    const plaintextCodes = this.plainRecoveryCodes(record);
    text(secret);
    return {
      attemptId: record.attemptId, expiresAt: record.expiresAt, secret,
      qrCodeUrl: await this.config.totp.generateQRCode({ handle: record.handle, secret, createdAt: new Date(record.createdAt) }),
      backupCodes: [...plaintextCodes],
    };
  }

  private plainRecoveryCodes(record: PendingRecord): string[] {
    const plaintextCodes: unknown = JSON.parse(this.config.totp.decrypt(record.recoveryCodes));
    if (!Array.isArray(plaintextCodes) || plaintextCodes.length !== record.backupCodes.codes.length || plaintextCodes.some((code, index) => typeof code !== 'string' || hashBackupCode(code) !== record.backupCodes.codes[index].hash)) fail('Pending backup-code material is inconsistent');
    return plaintextCodes as string[];
  }

  private filename(userId: string): string {
    text(userId);
    return path.join(this.directory, `${createHash('sha256').update(userId).digest('hex')}.json`);
  }

  private async readRecord(userId: string): Promise<EnrollmentRecord | null> {
    try {
      const record = parseRecord(JSON.parse(await fs.readFile(this.filename(userId), 'utf8')));
      if (this.recordUserId(record) !== userId) fail('Enrollment record identity does not match its filename');
      return record;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    }
  }

  private recordUserId(record: EnrollmentRecord): string {
    return record.state === 'pending' ? record.userId : record.receipt.userId;
  }

  private async recoverUnsafe(): Promise<void> {
    await fs.mkdir(this.directory, { recursive: true, mode: 0o700 });
    // A prior commit rename may have succeeded while its directory sync failed.
    // Acknowledge that publication before any durable projection is attempted.
    await this.syncDirectory();
    const entries = (await fs.readdir(this.directory)).sort();
    for (const entry of entries) {
      if (!entry.endsWith('.json')) continue; // Unpublished .tmp files have no authority.
      if (!/^[a-f0-9]{64}\.json$/.test(entry)) fail('Unexpected enrollment record filename');
      const record = parseRecord(JSON.parse(await fs.readFile(path.join(this.directory, entry), 'utf8')));
      if (path.basename(this.filename(this.recordUserId(record))) !== entry) fail('Enrollment record was moved under another identity');
      if (record.state === 'committed') await this.apply(record);
    }
    // Also resolve a previous rename whose directory-sync acknowledgement failed.
    await this.syncDirectory();
    const context = this.gate.context.getStore();
    if (context) context.state.recoveryRequired = false;
  }

  private async apply(record: CommittedRecord): Promise<void> {
    const context = this.gate.context.getStore();
    if (!context?.active || context.state.projecting) throw new TotpEnrollmentError('RECOVERY_REQUIRED', 'Enrollment projection requires exclusive authority');
    context.state.projecting = true;
    try {
      // A restart with the wrong encryption key must not activate an unusable
      // factor just because its journal and digest are structurally valid.
      const factor = record.completion.totpSecret;
      text(this.config.totp.decrypt({ encrypted: factor.encryptedSecret, iv: factor.iv, tag: factor.authTag, salt: factor.salt }));
      await this.config.project(copy(record.completion));
      // Only an unapplied commit may be replayed; remove its obsolete material.
      await this.writeRecord({ version: 1, state: 'applied', sessionDigest: record.completion.sessionDigest, receipt: record.receipt });
    } catch {
      throw new TotpEnrollmentError('RECOVERY_REQUIRED', 'Enrollment projection must recover before auth traffic can continue');
    } finally {
      context.state.projecting = false;
    }
  }

  /** Native #41 publication pattern, without its unrelated bootstrap API. */
  private async writeRecord(record: EnrollmentRecord): Promise<void> {
    parseRecord(record);
    await fs.mkdir(this.directory, { recursive: true, mode: 0o700 });
    const filename = this.filename(this.recordUserId(record));
    const temporary = `${filename}.${randomBytes(16).toString('hex')}.tmp`;
    try {
      const handle = await fs.open(temporary, 'wx', 0o600);
      try {
        await handle.writeFile(JSON.stringify(record), 'utf8');
        await handle.sync();
      } finally { await handle.close(); }
      await fs.rename(temporary, filename);
      await this.syncDirectory();
    } catch (error) {
      try { await fs.unlink(temporary); } catch { /* Unpublished temporary only. */ }
      throw error;
    }
  }

  private async syncDirectory(): Promise<void> {
    const directory = await fs.open(this.directory, 'r');
    try {
      // Fail closed if the configured filesystem cannot durably acknowledge.
      await directory.sync();
    } finally { await directory.close(); }
  }
}
