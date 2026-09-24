import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { createBackupCodeSet, generateBackupCodes } from '../core/backup-codes/index.js';
import type { TOTPService } from '../core/totp/index.js';
import type { AdminUser, BackupCodeSet, EncryptedData, EncryptedTOTPSecret } from '../types/auth.js';
import type { IStorageAdapter } from './interface.js';

export interface BootstrapProfile {
  displayName: string;
  bio: string;
  pronouns: string;
  /** App projection vocabulary; this metadata never controls auth grants. */
  visibility: 'public' | 'private' | 'unlisted' | 'draft' | 'published';
}

/** Only reference belongs in the httpOnly setup cookie. Never serialize the rest. */
export interface BootstrapSetup {
  reference: string;
  attemptId: string;
  handle: string;
  expiresAt: string;
  secret: string;
  qrCodeUrl: string;
  backupCodes: string[];
  backupCodesAcknowledged: boolean;
  profile?: BootstrapProfile;
}

export interface BootstrapCompletion {
  version: 1;
  attemptId: string;
  completedAt: string;
  user: AdminUser;
  totpSecret: EncryptedTOTPSecret;
  backupCodes: BackupCodeSet;
  profile?: BootstrapProfile;
}

/** Historical completion only, never a login/session credential. */
export interface BootstrapReceipt {
  version: 1;
  attemptId: string;
  userId: string;
  handle: string;
  completedAt: string;
  materialDigest: string;
}

export interface FileBootstrapConfig {
  /** One process owns this private durable directory, no multi-pod claims. */
  directory: string;
  /** Stable deployment/tenant context, authenticated inside every ciphertext. */
  scope: string;
  /** Use the existing configured encryption key; never a development fallback. */
  totp: Pick<TOTPService, 'generateSecret' | 'generateQRCode' | 'encrypt' | 'decrypt' | 'verifyTokenWithStep'>;
  /** Uncached canonical reads; these adapters must not reenter the auth gate. */
  storage: Pick<IStorageAdapter, 'getAllUsers' | 'getTOTPSecret' | 'getBackupCodes'>;
  /**
   * REQUIRED shared, awaited/reentrant single-writer gate used by ALL auth
   * initialization/mutations, including OAuth bootstrap and invitation writes.
   * Different coordinator instances for a root must share the same gate.
   * Do not pass a no-op mutex. Projection callbacks must use raw adapters.
   */
  withExclusiveAuth<T>(operation: () => Promise<T>): Promise<T>;
  /**
   * Optional trusted application namespace authority. Reject any pre-existing
   * content namespace, including directories, files and symlinks. Called under
   * the shared gate for NEW reservation and immediately before commit, never
   * on committed replay (which must accept only its frozen owned projection).
   * Read-only, raw adapters only; no auth-gate reentry or browser claims.
   */
  assertNamespaceAvailable?(handle: string): Promise<void>;
  /**
   * Durably project exactly these frozen records, preserving existing used
   * TOTP counters/backup codes. Check all material/owner conflicts; never
   * overwrite another account or recreate a removed account. Write factor,
   * backup hashes and optional profile BEFORE publishing the user with its
   * explicit frozen ID. An identical already-created user is an idempotent
   * replay, not permission to reset flags, credentials, roles or profile edits.
   * No session issuance, destructive rollback, network I/O or gate reentry.
   */
  project(completion: BootstrapCompletion): Promise<void>;
  ttlMs?: number;
  now?: () => Date;
}

export class BootstrapJournalError extends Error {
  constructor(readonly code: 'INVALID' | 'UNAUTHORIZED' | 'EXPIRED' | 'CONFLICT' | 'RECOVERY_REQUIRED', message: string) {
    super(message);
    this.name = 'BootstrapJournalError';
  }
}

interface Pending {
  state: 'pending';
  attemptId: string;
  referenceDigest: string;
  userId: string;
  handle: string;
  passwordHash: string;
  secret: string;
  backupCodes: string[];
  backupCodesAcknowledged: boolean;
  createdAt: string;
  expiresAt: string;
  profile?: BootstrapProfile;
}
interface Committed {
  state: 'committed';
  referenceDigest: string;
  completion: BootstrapCompletion;
  receipt: BootstrapReceipt;
}
interface Applied {
  state: 'applied';
  referenceDigest: string;
  receipt: BootstrapReceipt;
}
type RecordState = Pending | Committed | Applied;
const DOMAIN = 'tinyland-auth:bootstrap-journal:v1';
const MAX_TTL = 600_000;
const MAX_BYTES = 131_072;
const HEX = /^[a-f0-9]{64}$/;
function copy<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T; }
function invalid(): never { throw new BootstrapJournalError('INVALID', 'Invalid bootstrap material'); }
function object(value: unknown, required: string[], optional: string[] = []): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const keys = Object.keys(value);
  if (required.some((key) => !keys.includes(key)) || keys.some((key) => !required.includes(key) && !optional.includes(key))) invalid();
}
function text(value: unknown, max = 1024): asserts value is string {
  if (typeof value !== 'string' || !value.length || value.length > max) invalid();
}
function iso(value: unknown): asserts value is string {
  text(value, 24);
  if (!Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) invalid();
}
function hex(value: unknown): asserts value is string { if (typeof value !== 'string' || !HEX.test(value)) invalid(); }
function handle(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9_-]{2,29}$/.test(value)) invalid();
}
function passwordHash(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^\$2[aby]\$(0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}$/.test(value)) invalid();
}
function profile(value: unknown): asserts value is BootstrapProfile {
  object(value, ['displayName', 'bio', 'pronouns', 'visibility']);
  text(value.displayName, 200);
  for (const key of ['bio', 'pronouns']) if (typeof value[key] !== 'string' || (value[key] as string).length > (key === 'bio' ? 4096 : 200)) invalid();
  if (!['public', 'private', 'unlisted', 'draft', 'published'].includes(value.visibility as string)) invalid();
}
function encrypted(value: unknown): asserts value is EncryptedData {
  object(value, ['encrypted', 'salt', 'iv', 'tag']);
  for (const key of ['encrypted', 'salt', 'iv', 'tag']) {
    text(value[key], MAX_BYTES);
    const field = value[key] as string;
    if (Buffer.from(field, 'base64').toString('base64') !== field) invalid();
  }
  if (Buffer.from(value.salt as string, 'base64').length !== 32 || Buffer.from(value.iv as string, 'base64').length !== 16 || Buffer.from(value.tag as string, 'base64').length !== 16) invalid();
}
function referenceDigest(reference: string): string {
  if (typeof reference !== 'string' || !HEX.test(reference)) throw new BootstrapJournalError('UNAUTHORIZED', 'Bootstrap reference is unavailable');
  return createHash('sha256').update(`${DOMAIN}:reference\0`).update(reference).digest('hex');
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function materialDigest(completion: BootstrapCompletion): string {
  return createHash('sha256').update(`${DOMAIN}:completion\0`).update(canonical(completion)).digest('hex');
}
function receipt(value: unknown): asserts value is BootstrapReceipt {
  object(value, ['version', 'attemptId', 'userId', 'handle', 'completedAt', 'materialDigest']);
  if (value.version !== 1) invalid();
  hex(value.attemptId); text(value.userId, 128); handle(value.handle); iso(value.completedAt); hex(value.materialDigest);
}
function completion(value: unknown): asserts value is BootstrapCompletion {
  object(value, ['version', 'attemptId', 'completedAt', 'user', 'totpSecret', 'backupCodes'], ['profile']);
  if (value.version !== 1) invalid();
  hex(value.attemptId); iso(value.completedAt);
  if (value.profile !== undefined) profile(value.profile);
  object(value.user, ['id', 'handle', 'passwordHash', 'role', 'isActive', 'totpEnabled', 'totpSecretId', 'needsOnboarding', 'onboardingStep', 'createdAt', 'updatedAt']);
  const user = value.user;
  text(user.id, 128); handle(user.handle); passwordHash(user.passwordHash);
  if (user.role !== 'super_admin' || user.isActive !== true || user.totpEnabled !== true || user.totpSecretId !== user.handle || user.needsOnboarding !== false || user.onboardingStep !== 0 || user.createdAt !== value.completedAt || user.updatedAt !== value.completedAt) invalid();
  object(value.totpSecret, ['userId', 'handle', 'encryptedSecret', 'iv', 'authTag', 'salt', 'createdAt', 'lastUsedAt', 'lastUsedTotpStep', 'backupCodesGenerated', 'version']);
  const factor = value.totpSecret;
  encrypted({ encrypted: factor.encryptedSecret, iv: factor.iv, tag: factor.authTag, salt: factor.salt });
  if (factor.userId !== user.id || factor.handle !== user.handle || factor.createdAt !== value.completedAt || factor.lastUsedAt !== value.completedAt || !Number.isSafeInteger(factor.lastUsedTotpStep) || (factor.lastUsedTotpStep as number) < 0 || factor.backupCodesGenerated !== true || factor.version !== 1) invalid();
  object(value.backupCodes, ['userId', 'codes', 'generatedAt']);
  const codes = value.backupCodes;
  if (codes.userId !== user.id || codes.generatedAt !== value.completedAt || !Array.isArray(codes.codes) || codes.codes.length !== 10) invalid();
  const ids = new Set<string>();
  for (const code of codes.codes) {
    object(code, ['id', 'hash', 'used']); text(code.id, 128); hex(code.hash);
    if (code.used !== false || ids.has(code.id)) invalid();
    ids.add(code.id);
  }
}
function record(value: unknown): asserts value is RecordState {
  if (!value || typeof value !== 'object' || !('state' in value)) invalid();
  if (value.state === 'pending') {
    object(value, ['state', 'attemptId', 'referenceDigest', 'userId', 'handle', 'passwordHash', 'secret', 'backupCodes', 'backupCodesAcknowledged', 'createdAt', 'expiresAt'], ['profile']);
    hex(value.attemptId); hex(value.referenceDigest); text(value.userId, 128); handle(value.handle); passwordHash(value.passwordHash);
    if (typeof value.secret !== 'string' || !/^[A-Z2-7]{16,256}$/.test(value.secret)) invalid();
    if (!Array.isArray(value.backupCodes) || value.backupCodes.length !== 10 || value.backupCodes.some((code) => typeof code !== 'string' || !/^[A-F0-9]{4}-[A-F0-9]{4}$/.test(code)) || new Set(value.backupCodes).size !== 10) invalid();
    if (typeof value.backupCodesAcknowledged !== 'boolean') invalid();
    iso(value.createdAt); iso(value.expiresAt);
    if (Date.parse(value.expiresAt) <= Date.parse(value.createdAt) || Date.parse(value.expiresAt) - Date.parse(value.createdAt) > MAX_TTL) invalid();
    if (value.profile !== undefined) profile(value.profile);
  } else if (value.state === 'committed') {
    object(value, ['state', 'referenceDigest', 'completion', 'receipt']); hex(value.referenceDigest); completion(value.completion); receipt(value.receipt);
    const c = value.completion; const r = value.receipt;
    if (r.attemptId !== c.attemptId || r.userId !== c.user.id || r.handle !== c.user.handle || r.completedAt !== c.completedAt || r.materialDigest !== materialDigest(c)) invalid();
  } else if (value.state === 'applied') {
    object(value, ['state', 'referenceDigest', 'receipt']); hex(value.referenceDigest); receipt(value.receipt);
  } else invalid();
}

/** Opt-in encrypted file authority; legacy BootstrapService is unchanged. */
export class FileBootstrapCoordinator {
  private readonly directory: string;
  private readonly filename: string;
  private readonly ttl: number;
  private readonly now: () => Date;
  constructor(private readonly config: FileBootstrapConfig) {
    text(config.directory, 4096); text(config.scope, 200);
    if (typeof config.withExclusiveAuth !== 'function') invalid();
    if (config.assertNamespaceAvailable !== undefined && typeof config.assertNamespaceAvailable !== 'function') invalid();
    this.directory = path.resolve(config.directory);
    this.filename = path.join(this.directory, 'bootstrap.json');
    this.ttl = config.ttlMs ?? MAX_TTL;
    if (!Number.isSafeInteger(this.ttl) || this.ttl <= 0 || this.ttl > MAX_TTL) invalid();
    this.now = config.now ?? (() => new Date());
  }

  /** No journal => no writes, including installations with existing users. */
  async recover(): Promise<void> { return this.config.withExclusiveAuth(() => this.recoverUnsafe()); }

  /** Caller must hold the SAME auth gate across any alternative initialization. */
  async assertAvailable(): Promise<void> {
    return this.config.withExclusiveAuth(async () => {
      await this.recoverUnsafe();
      const prior = await this.readRecord();
      if (prior && (prior.state !== 'pending' || Date.parse(prior.expiresAt) > this.now().getTime())) this.conflict();
      await this.empty();
    });
  }

  async begin(input: { handle: string; passwordHash: string; profile?: BootstrapProfile }): Promise<BootstrapSetup> {
    const requested = copy(input);
    object(requested, ['handle', 'passwordHash'], ['profile']);
    // Normalize only a NEW initial identity. Never rewrite existing users or
    // normalize an authenticated journal record during parsing/recovery.
    text(requested.handle, 128);
    requested.handle = requested.handle.trim().toLowerCase();
    handle(requested.handle); passwordHash(requested.passwordHash);
    if (requested.profile !== undefined) profile(requested.profile);
    return this.config.withExclusiveAuth(async () => {
      await this.recoverUnsafe();
      const prior = await this.readRecord();
      if (prior && (prior.state !== 'pending' || Date.parse(prior.expiresAt) > this.now().getTime())) this.conflict();
      await this.empty();
      await this.namespaceAvailable(requested.handle);
      const createdAt = this.now().toISOString();
      const reference = randomBytes(32).toString('hex');
      const generated = await this.config.totp.generateSecret(requested.handle);
      const pending: Pending = {
        state: 'pending', attemptId: randomBytes(32).toString('hex'), referenceDigest: referenceDigest(reference),
        userId: randomUUID(), handle: requested.handle, passwordHash: requested.passwordHash,
        secret: generated.secret, backupCodes: generateBackupCodes(), backupCodesAcknowledged: false, createdAt,
        expiresAt: new Date(Date.parse(createdAt) + this.ttl).toISOString(),
        ...(requested.profile ? { profile: requested.profile } : {}),
      };
      record(pending);
      const setup = await this.setup(pending, reference);
      await this.namespaceAvailable(pending.handle);
      await this.empty(pending); this.unexpired(pending);
      await this.writeRecord(pending);
      // I/O may finish after expiry or a noncooperating external writer acts.
      await this.empty(pending); this.unexpired(pending);
      return setup;
    });
  }

  async read(reference: string): Promise<BootstrapSetup> {
    return this.config.withExclusiveAuth(async () => {
      await this.recoverUnsafe();
      const pending = await this.pending(reference);
      const setup = await this.setup(pending, reference);
      await this.empty(pending); this.unexpired(pending);
      return setup;
    });
  }

  async updateProfile(reference: string, value: BootstrapProfile): Promise<void> {
    const requested = copy(value); profile(requested);
    return this.config.withExclusiveAuth(async () => {
      await this.recoverUnsafe();
      const pending = await this.pending(reference);
      const next: Pending = { ...pending, profile: requested };
      await this.empty(next); this.unexpired(next);
      await this.writeRecord(next);
      await this.empty(next); this.unexpired(next);
    });
  }

  /** Server action records explicit acknowledgment of THIS attempt's codes. */
  async acknowledgeBackupCodes(reference: string): Promise<void> {
    return this.config.withExclusiveAuth(async () => {
      await this.recoverUnsafe();
      const pending = await this.pending(reference);
      if (pending.backupCodesAcknowledged) return;
      const acknowledged: Pending = { ...pending, backupCodesAcknowledged: true };
      await this.empty(acknowledged); this.unexpired(acknowledged);
      await this.writeRecord(acknowledged);
      await this.empty(acknowledged); this.unexpired(acknowledged);
    });
  }

  async complete(input: { reference: string; token: string }): Promise<BootstrapReceipt> {
    const { reference, token } = input;
    return this.config.withExclusiveAuth(async () => {
      await this.recoverUnsafe();
      const prior = await this.readRecord();
      if (prior?.state === 'applied') { this.bind(prior, reference); return copy(prior.receipt); }
      const pending = await this.pending(reference);
      if (!pending.backupCodesAcknowledged) throw new BootstrapJournalError('INVALID', 'Confirm that the backup codes have been saved before completing setup');
      if (typeof token !== 'string' || !/^\d{6}$/.test(token)) invalid();
      const verified = await this.config.totp.verifyTokenWithStep({ handle: pending.handle, secret: pending.secret, createdAt: new Date(pending.createdAt) }, token);
      if (!verified.valid || !Number.isSafeInteger(verified.step) || verified.step! < 0) invalid();
      await this.empty(pending); this.unexpired(pending);
      const cipher = this.config.totp.encrypt(pending.secret);
      if (this.config.totp.decrypt(cipher) !== pending.secret) invalid();
      const completedAt = this.now().toISOString();
      const material: BootstrapCompletion = {
        version: 1, attemptId: pending.attemptId, completedAt,
        user: {
          id: pending.userId, handle: pending.handle, passwordHash: pending.passwordHash,
          role: 'super_admin', isActive: true, totpEnabled: true, totpSecretId: pending.handle,
          needsOnboarding: false, onboardingStep: 0, createdAt: completedAt, updatedAt: completedAt,
        },
        totpSecret: {
          userId: pending.userId, handle: pending.handle, encryptedSecret: cipher.encrypted, salt: cipher.salt, iv: cipher.iv, authTag: cipher.tag,
          createdAt: completedAt, lastUsedAt: completedAt, lastUsedTotpStep: verified.step,
          backupCodesGenerated: true, version: 1,
        },
        backupCodes: { ...createBackupCodeSet(pending.userId, pending.backupCodes), generatedAt: completedAt },
        ...(pending.profile ? { profile: pending.profile } : {}),
      };
      const safeReceipt: BootstrapReceipt = {
        version: 1, attemptId: pending.attemptId, userId: pending.userId, handle: pending.handle,
        completedAt, materialDigest: materialDigest(material),
      };
      const committed: Committed = { state: 'committed', referenceDigest: pending.referenceDigest, completion: material, receipt: safeReceipt };
      record(committed);
      await this.namespaceAvailable(pending.handle);
      await this.empty(pending); this.unexpired(pending);
      // The durable record, not the browser, is authority for crash replay.
      await this.writeRecord(committed);
      await this.apply(committed);
      return copy(safeReceipt);
    });
  }

  private conflict(): never { throw new BootstrapJournalError('CONFLICT', 'Bootstrap state requires review or is unavailable'); }
  private async namespaceAvailable(handle: string): Promise<void> {
    try { await this.config.assertNamespaceAvailable?.(handle); } catch { this.conflict(); }
  }
  private unexpired(pending: Pending): void {
    if (this.now().getTime() < Date.parse(pending.createdAt) || this.now().getTime() >= Date.parse(pending.expiresAt)) throw new BootstrapJournalError('EXPIRED', 'Bootstrap setup expired');
  }
  private bind(value: RecordState, reference: string): void {
    if (!timingSafeEqual(Buffer.from(value.referenceDigest, 'hex'), Buffer.from(referenceDigest(reference), 'hex'))) throw new BootstrapJournalError('UNAUTHORIZED', 'Bootstrap reference is unavailable');
  }
  private async empty(candidate?: Pick<Pending, 'userId' | 'handle'>): Promise<void> {
    if ((await this.config.storage.getAllUsers()).length) this.conflict();
    if (candidate && (await this.config.storage.getTOTPSecret(candidate.handle) || await this.config.storage.getBackupCodes(candidate.userId))) this.conflict();
  }
  private async pending(reference: string): Promise<Pending> {
    referenceDigest(reference);
    const value = await this.readRecord();
    if (!value || value.state !== 'pending') throw new BootstrapJournalError('UNAUTHORIZED', 'Bootstrap setup is unavailable');
    this.bind(value, reference); await this.empty(value); this.unexpired(value);
    return value;
  }
  private async setup(value: Pending, reference: string): Promise<BootstrapSetup> {
    return {
      reference, attemptId: value.attemptId, handle: value.handle, expiresAt: value.expiresAt,
      secret: value.secret, backupCodes: [...value.backupCodes], backupCodesAcknowledged: value.backupCodesAcknowledged,
      qrCodeUrl: await this.config.totp.generateQRCode({ handle: value.handle, secret: value.secret, createdAt: new Date(value.createdAt) }),
      ...(value.profile ? { profile: copy(value.profile) } : {}),
    };
  }
  private async recoverUnsafe(): Promise<void> {
    try {
      const value = await this.readRecord();
      if (!value) return;
      // A previous rename may have succeeded even if directory fsync failed.
      await this.syncDirectory(this.directory);
      if (value.state === 'committed') await this.apply(value);
    } catch {
      throw new BootstrapJournalError('RECOVERY_REQUIRED', 'Bootstrap recovery is required before authentication can continue');
    }
  }

  private async checkProjection(value: BootstrapCompletion, finished: boolean): Promise<void> {
    const users = await this.config.storage.getAllUsers();
    if (users.length > 1) this.conflict();
    const user = users[0];
    if (user) {
      const fixed = ['id', 'handle', 'passwordHash', 'role', 'isActive', 'totpEnabled', 'totpSecretId', 'needsOnboarding', 'onboardingStep', 'createdAt'] as const;
      if (fixed.some((key) => user[key] !== value.user[key]) || user.isLocked === true || user.firstLogin === true || Object.hasOwn(user, 'removedAt') || Object.hasOwn(user, 'removedBy')) this.conflict();
    } else if (finished) this.conflict();
    const factor = await this.config.storage.getTOTPSecret(value.user.handle);
    if (factor) {
      const fixed = ['userId', 'handle', 'encryptedSecret', 'iv', 'authTag', 'salt', 'createdAt', 'backupCodesGenerated', 'version'] as const;
      if (fixed.some((key) => factor[key] !== value.totpSecret[key]) || !Number.isSafeInteger(factor.lastUsedTotpStep) || factor.lastUsedTotpStep! < value.totpSecret.lastUsedTotpStep!) this.conflict();
      if (factor.lastUsedAt !== undefined) iso(factor.lastUsedAt);
    } else if (finished || user) this.conflict();
    const codes = await this.config.storage.getBackupCodes(value.user.id);
    if (codes) {
      if (codes.userId !== value.user.id || codes.generatedAt !== value.backupCodes.generatedAt || codes.codes.length !== value.backupCodes.codes.length || new Set(codes.codes.map((code) => code.id)).size !== codes.codes.length) this.conflict();
      for (const code of value.backupCodes.codes) {
        const existing = codes.codes.find((item) => item.id === code.id);
        if (!existing || existing.hash !== code.hash || typeof existing.used !== 'boolean') this.conflict();
        if (existing.usedAt !== undefined) iso(existing.usedAt);
      }
      if (codes.lastUsedAt !== undefined) iso(codes.lastUsedAt);
    } else if (finished || user) this.conflict();
  }
  private async apply(value: Committed): Promise<void> {
    try {
      const factor = value.completion.totpSecret;
      text(this.config.totp.decrypt({ encrypted: factor.encryptedSecret, iv: factor.iv, tag: factor.authTag, salt: factor.salt }));
      await this.checkProjection(value.completion, false);
      await this.config.project(copy(value.completion));
      await this.checkProjection(value.completion, true);
      await this.writeRecord({ state: 'applied', referenceDigest: value.referenceDigest, receipt: value.receipt });
    } catch {
      throw new BootstrapJournalError('RECOVERY_REQUIRED', 'Bootstrap projection must recover before authentication can continue');
    }
  }
  private async readRecord(): Promise<RecordState | null> {
    let serialized: string;
    try {
      const info = await fs.lstat(this.filename);
      if (!info.isFile() || info.size > MAX_BYTES) invalid();
      serialized = await fs.readFile(this.filename, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    }
    if (Buffer.byteLength(serialized) > MAX_BYTES) invalid();
    const envelope: unknown = JSON.parse(serialized);
    object(envelope, ['version', 'encrypted']);
    if (envelope.version !== 1) invalid();
    encrypted(envelope.encrypted);
    const authenticated: unknown = JSON.parse(this.config.totp.decrypt(envelope.encrypted));
    object(authenticated, ['domain', 'scope', 'record']);
    if (authenticated.domain !== DOMAIN || authenticated.scope !== this.config.scope) invalid();
    record(authenticated.record);
    return authenticated.record;
  }
  private async writeRecord(value: RecordState): Promise<void> {
    record(value);
    // Domain and scope are INSIDE authenticated AES-GCM plaintext: substituting
    // another factor/journal ciphertext cannot produce a valid bootstrap record.
    const plaintext = JSON.stringify({ domain: DOMAIN, scope: this.config.scope, record: value });
    const cipher = this.config.totp.encrypt(plaintext); encrypted(cipher);
    if (this.config.totp.decrypt(cipher) !== plaintext) invalid();
    const serialized = JSON.stringify({ version: 1, encrypted: cipher });
    if (Buffer.byteLength(serialized) > MAX_BYTES) invalid();
    const firstCreated = await fs.mkdir(this.directory, { recursive: true, mode: 0o700 });
    if (firstCreated) {
      // Persist newly-created directory entries, including recursive parents.
      let current = this.directory;
      const stop = path.dirname(firstCreated);
      for (;;) {
        await this.syncDirectory(current);
        if (current === stop) break;
        current = path.dirname(current);
      }
    }
    const temporary = `${this.filename}.${randomBytes(16).toString('hex')}.tmp`;
    try {
      const file = await fs.open(temporary, 'wx', 0o600);
      try { await file.writeFile(serialized, 'utf8'); await file.sync(); } finally { await file.close(); }
      await fs.rename(temporary, this.filename);
      await this.syncDirectory(this.directory);
    } catch (error) {
      try { await fs.unlink(temporary); } catch { /* Unpublished temporary only. */ }
      throw error;
    }
  }
  private async syncDirectory(directory: string): Promise<void> {
    const file = await fs.open(directory, 'r');
    try { await file.sync(); } finally { await file.close(); }
  }
}
