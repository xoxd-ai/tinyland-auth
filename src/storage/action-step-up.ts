import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

/** These values are freshly computed by the application from durable authority. */
export interface ActionStepUpIdentity {
  userId: string;
  sessionBinding: string;
  credentialBinding: string;
  authorityBinding: string;
  factorBinding: string;
}

export type ActionStepUpAction =
  | 'user.password.reset' | 'user.access.update' | 'user.remove'
  | 'factor.disable' | 'federation.activate'
  | 'invitation.create' | 'invitation.extend';

export interface ActionStepUpBinding extends ActionStepUpIdentity {
  action: ActionStepUpAction;
  resourceKind: 'user' | 'invitation';
  resourceId: string;
  /** HMAC of validated, normalized intent; never a raw password or unkeyed hash. */
  intentDigest: string;
  /** HMAC of relevant current target state, recomputed before consumption. */
  targetDigest: string;
}

export interface ActionStepUpChallenge { challengeId: string; expiresAt: string }
export interface ActionStepUpPermit extends ActionStepUpChallenge { permitId: string }
export interface ActionStepUpReceipt {
  receiptId: string;
  userId: string;
  factorBinding: string;
  action: ActionStepUpAction;
  resourceId: string;
}

export interface FileActionStepUpConfig {
  /** Dedicated private directory, owned by one application process. */
  directory: string;
  /** Existing auth key custody (AUTH_SECRET, else TOTP_ENCRYPTION_KEY). */
  signingKey: () => string;
  now?: () => number;
  ttlMs?: number;
  maxRecords?: number;
  maxFailures?: number;
}

export class ActionStepUpError extends Error {
  constructor(readonly code: 'INVALID' | 'EXPIRED' | 'UNAUTHORIZED' | 'CONFLICT' | 'UNAVAILABLE', message: string) {
    super(message);
    this.name = 'ActionStepUpError';
  }
}

type StepUpState = 'pending' | 'verified' | 'consumed';
interface StepUpRecord {
  version: 1;
  state: StepUpState;
  referenceDigest: string;
  identityDigest: string;
  bindingDigest: string;
  userDigest: string;
  factorBinding: string;
  action: ActionStepUpAction;
  resourceKind: 'user' | 'invitation';
  resourceDigest: string;
  intentDigest: string;
  targetDigest: string;
  createdAt: number;
  expiresAt: number;
  failures: number;
  verifiedAt?: number;
  permitDigest?: string;
  consumedAt?: number;
  receiptDigest?: string;
}
interface Envelope { version: 1; record: StepUpRecord; seal: string }

const ACTIONS: ReadonlySet<string> = new Set([
  'user.password.reset', 'user.access.update', 'user.remove', 'factor.disable',
  'federation.activate', 'invitation.create', 'invitation.extend',
]);
const HEX64 = /^[a-f0-9]{64}$/;
const REFERENCE = /^[A-Za-z0-9_-]{43}$/;
const MAX_TTL_MS = 5 * 60 * 1000;
const MAX_RECORDS = 4096;
const MAX_FAILURES = 5;
const directoryQueues = new Map<string, Promise<void>>();

function assertKeys(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ActionStepUpError('INVALID', 'Invalid step-up record');
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new ActionStepUpError('INVALID', 'Unexpected step-up record fields');
  }
}

function assertText(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256 || value.includes('\0')) {
    throw new ActionStepUpError('INVALID', 'Invalid step-up binding');
  }
}

function assertDigest(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !HEX64.test(value)) throw new ActionStepUpError('INVALID', 'Invalid step-up digest');
}

function assertIdentity(identity: ActionStepUpIdentity): void {
  assertText(identity.userId);
  for (const field of ['sessionBinding', 'credentialBinding', 'authorityBinding', 'factorBinding'] as const) {
    assertDigest(identity[field]);
  }
}

function assertBinding(binding: ActionStepUpBinding): void {
  assertIdentity(binding);
  if (!ACTIONS.has(binding.action)) throw new ActionStepUpError('INVALID', 'Unknown step-up action');
  if (binding.resourceKind !== 'user' && binding.resourceKind !== 'invitation') {
    throw new ActionStepUpError('INVALID', 'Unknown step-up resource');
  }
  assertText(binding.resourceId);
  assertDigest(binding.intentDigest);
  assertDigest(binding.targetDigest);
}

function identityValues(identity: ActionStepUpIdentity): readonly string[] {
  return [identity.userId, identity.sessionBinding, identity.credentialBinding,
    identity.authorityBinding, identity.factorBinding];
}

function bindingValues(binding: ActionStepUpBinding): readonly string[] {
  return [...identityValues(binding), binding.action, binding.resourceKind, binding.resourceId,
    binding.intentDigest, binding.targetDigest];
}

function equalDigest(left: string, right: string): boolean {
  return HEX64.test(left) && HEX64.test(right) && timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function assertRecord(value: unknown): asserts value is StepUpRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ActionStepUpError('INVALID', 'Invalid step-up record');
  const candidate = value as Record<string, unknown>;
  const common = ['version', 'state', 'referenceDigest', 'identityDigest', 'bindingDigest',
    'userDigest', 'factorBinding', 'action', 'resourceKind', 'resourceDigest',
    'intentDigest', 'targetDigest', 'createdAt', 'expiresAt', 'failures'];
  if (candidate.state === 'pending') assertKeys(value, common);
  else if (candidate.state === 'verified') assertKeys(value, [...common, 'verifiedAt', 'permitDigest']);
  else if (candidate.state === 'consumed') assertKeys(value, [...common, 'verifiedAt', 'permitDigest', 'consumedAt', 'receiptDigest']);
  else throw new ActionStepUpError('INVALID', 'Unknown step-up state');
  const record = candidate;
  if (record.version !== 1 || typeof record.action !== 'string' || !ACTIONS.has(record.action) ||
      (record.resourceKind !== 'user' && record.resourceKind !== 'invitation')) {
    throw new ActionStepUpError('INVALID', 'Invalid step-up record authority');
  }
  for (const field of ['referenceDigest', 'identityDigest', 'bindingDigest', 'userDigest',
    'factorBinding', 'resourceDigest', 'intentDigest', 'targetDigest'] as const) assertDigest(record[field]);
  if (typeof record.createdAt !== 'number' || typeof record.expiresAt !== 'number' ||
      !Number.isSafeInteger(record.createdAt) || !Number.isSafeInteger(record.expiresAt) ||
      record.expiresAt <= record.createdAt || record.expiresAt - record.createdAt > MAX_TTL_MS ||
      typeof record.failures !== 'number' || !Number.isSafeInteger(record.failures) || record.failures < 0 || record.failures > MAX_FAILURES) {
    throw new ActionStepUpError('INVALID', 'Invalid step-up lifetime or failure count');
  }
  if (record.state !== 'pending' && (typeof record.verifiedAt !== 'number' || !Number.isSafeInteger(record.verifiedAt) ||
      record.verifiedAt < record.createdAt || record.verifiedAt >= record.expiresAt)) {
    throw new ActionStepUpError('INVALID', 'Invalid verification time');
  }
  if (record.state !== 'pending') assertDigest(record.permitDigest);
  if (record.state === 'consumed' && (typeof record.consumedAt !== 'number' || typeof record.verifiedAt !== 'number' ||
      !Number.isSafeInteger(record.consumedAt) || record.consumedAt < record.verifiedAt || record.consumedAt >= record.expiresAt)) {
    throw new ActionStepUpError('INVALID', 'Invalid consumption time');
  }
  if (record.state === 'consumed') assertDigest(record.receiptDigest);
}

/** A directory-wide queue serializes all challenge transitions and capacity pruning. */
async function queued<T>(directory: string, operation: () => Promise<T>): Promise<T> {
  const prior = directoryQueues.get(directory) ?? Promise.resolve();
  let release!: () => void;
  const tail = new Promise<void>((resolve) => { release = resolve; });
  directoryQueues.set(directory, tail);
  await prior;
  try { return await operation(); }
  finally {
    release();
    if (directoryQueues.get(directory) === tail) directoryQueues.delete(directory);
  }
}

/** Private, single-writer action permits; the caller owns its outer auth gate. */
export class FileActionStepUpStore {
  private readonly directory: string;
  private readonly now: () => number;
  private readonly ttlMs: number;
  private readonly maxRecords: number;
  private readonly maxFailures: number;

  constructor(private readonly config: FileActionStepUpConfig) {
    if (!config.directory) throw new ActionStepUpError('INVALID', 'Step-up directory is required');
    this.directory = path.resolve(config.directory);
    this.now = config.now ?? Date.now;
    this.ttlMs = config.ttlMs ?? MAX_TTL_MS;
    this.maxRecords = config.maxRecords ?? MAX_RECORDS;
    this.maxFailures = config.maxFailures ?? MAX_FAILURES;
    if (!Number.isSafeInteger(this.ttlMs) || this.ttlMs <= 0 || this.ttlMs > MAX_TTL_MS ||
        !Number.isSafeInteger(this.maxRecords) || this.maxRecords <= 0 || this.maxRecords > MAX_RECORDS ||
        !Number.isSafeInteger(this.maxFailures) || this.maxFailures <= 0 || this.maxFailures > MAX_FAILURES) {
      throw new ActionStepUpError('INVALID', 'Invalid step-up limits');
    }
  }

  async issue(binding: ActionStepUpBinding): Promise<ActionStepUpChallenge> {
    assertBinding(binding);
    return queued(this.directory, async () => {
      await this.prepare();
      const liveCount = await this.pruneExpired();
      if (liveCount >= this.maxRecords) throw new ActionStepUpError('UNAVAILABLE', 'Step-up capacity is unavailable');
      const now = this.clock();
      const challengeId = randomBytes(32).toString('base64url');
      const record: StepUpRecord = {
        version: 1, state: 'pending',
        referenceDigest: this.digest('reference', challengeId),
        identityDigest: this.digest('identity', JSON.stringify(identityValues(binding))),
        bindingDigest: this.digest('binding', JSON.stringify(bindingValues(binding))),
        userDigest: this.digest('user', binding.userId), factorBinding: binding.factorBinding,
        action: binding.action, resourceKind: binding.resourceKind,
        resourceDigest: this.digest('resource', binding.resourceId),
        intentDigest: binding.intentDigest, targetDigest: binding.targetDigest,
        createdAt: now, expiresAt: now + this.ttlMs, failures: 0,
      };
      await this.write(record);
      this.assertLive(record);
      return { challengeId, expiresAt: new Date(record.expiresAt).toISOString() };
    });
  }

  /** verifyFactor must perform a real TOTP check and persist its used step once. */
  async verify(input: { challengeId: string; identity: ActionStepUpIdentity }, verifyFactor: () => Promise<boolean>): Promise<ActionStepUpPermit> {
    assertIdentity(input.identity);
    this.assertReference(input.challengeId);
    return queued(this.directory, async () => {
      await this.prepare();
      const record = await this.read(input.challengeId);
      this.assertIdentityMatch(record, input.identity);
      this.assertLive(record);
      if (record.state === 'consumed') throw new ActionStepUpError('CONFLICT', 'Step-up permit was consumed');
      // The permit reference is never stored in plaintext. A lost verify ACK
      // deliberately burns this challenge rather than disclosing a permit that
      // may have been published after an fsync failure.
      if (record.state === 'verified') throw new ActionStepUpError('CONFLICT', 'Step-up challenge was already verified');
      if (record.failures >= this.maxFailures) throw new ActionStepUpError('UNAUTHORIZED', 'Step-up verification budget exhausted');
      let valid: boolean;
      try { valid = await verifyFactor(); }
      catch { throw new ActionStepUpError('UNAVAILABLE', 'Step-up factor verification is unavailable'); }
      this.assertLive(record);
      if (valid !== true) {
        await this.write({ ...record, failures: record.failures + 1 });
        throw new ActionStepUpError('UNAUTHORIZED', 'Invalid step-up factor');
      }
      const permitId = randomBytes(32).toString('base64url');
      const verifiedAt = this.clock();
      if (verifiedAt >= record.expiresAt) throw new ActionStepUpError('EXPIRED', 'Step-up permit expired');
      await this.write({ ...record, state: 'verified', verifiedAt, permitDigest: this.digest('permit', permitId) });
      this.assertLive(record);
      return { challengeId: input.challengeId, permitId, expiresAt: new Date(record.expiresAt).toISOString() };
    });
  }

  /** Durable consumption precedes the caller's business mutation. */
  async consume(input: { challengeId: string; permitId: string; binding: ActionStepUpBinding }): Promise<ActionStepUpReceipt> {
    assertBinding(input.binding);
    this.assertReference(input.challengeId);
    this.assertReference(input.permitId);
    return queued(this.directory, async () => {
      await this.prepare();
      const record = await this.read(input.challengeId);
      this.assertBindingMatch(record, input.binding);
      this.assertLive(record);
      if (record.state !== 'verified') throw new ActionStepUpError('CONFLICT', 'Step-up permit is not verified');
      if (!equalDigest(record.permitDigest!, this.digest('permit', input.permitId))) {
        throw new ActionStepUpError('UNAUTHORIZED', 'Invalid step-up permit');
      }
      const receiptId = randomBytes(32).toString('base64url');
      const consumedAt = this.clock();
      if (consumedAt >= record.expiresAt) throw new ActionStepUpError('EXPIRED', 'Step-up permit expired');
      await this.write({ ...record, state: 'consumed', consumedAt,
        receiptDigest: this.digest('receipt', receiptId) });
      this.assertLive(record);
      return { receiptId, userId: input.binding.userId, factorBinding: input.binding.factorBinding,
        action: input.binding.action, resourceId: input.binding.resourceId };
    });
  }

  private clock(): number {
    const now = this.now();
    if (!Number.isSafeInteger(now)) throw new ActionStepUpError('UNAVAILABLE', 'Step-up clock is unavailable');
    return now;
  }

  private key(): Buffer {
    let key: string;
    try { key = this.config.signingKey(); }
    catch { throw new ActionStepUpError('UNAVAILABLE', 'Step-up signing custody is unavailable'); }
    if (typeof key !== 'string' || Buffer.byteLength(key, 'utf8') < 32) {
      throw new ActionStepUpError('UNAVAILABLE', 'Step-up signing custody is unavailable');
    }
    return Buffer.from(key, 'utf8');
  }

  private digest(domain: string, value: string): string {
    return createHmac('sha256', this.key()).update(`tinyland-auth:action-step-up:${domain}:v1\0`).update(value).digest('hex');
  }

  private assertReference(reference: string): void {
    if (typeof reference !== 'string' || !REFERENCE.test(reference)) throw new ActionStepUpError('INVALID', 'Invalid step-up reference');
  }

  private filename(referenceDigest: string): string { return path.join(this.directory, `${referenceDigest}.json`); }

  private async syncDirectory(): Promise<void> {
    const handle = await fs.open(this.directory, 'r');
    try { await handle.sync(); } finally { await handle.close(); }
  }

  private async prepare(): Promise<void> {
    try {
      await fs.mkdir(this.directory, { recursive: true, mode: 0o700 });
      const state = await fs.lstat(this.directory);
      if (!state.isDirectory() || state.isSymbolicLink()) throw new Error('Untrusted step-up directory');
      await fs.chmod(this.directory, 0o700);
      // Every queued read first acknowledges a possible prior post-rename
      // sync failure, including after restart. Until this succeeds, no permit
      // is observable through the store.
      await this.syncDirectory();
    } catch { throw new ActionStepUpError('UNAVAILABLE', 'Step-up storage is unavailable'); }
  }

  private async read(reference: string): Promise<StepUpRecord> {
    const expectedDigest = this.digest('reference', reference);
    let raw: string;
    try { raw = await fs.readFile(this.filename(expectedDigest), 'utf8'); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new ActionStepUpError('INVALID', 'Unknown step-up reference');
      throw new ActionStepUpError('UNAVAILABLE', 'Step-up storage is unavailable');
    }
    let parsed: unknown;
    try { parsed = JSON.parse(raw); } catch { throw new ActionStepUpError('INVALID', 'Invalid step-up record'); }
    assertKeys(parsed, ['version', 'record', 'seal']);
    if (parsed.version !== 1) throw new ActionStepUpError('INVALID', 'Unsupported step-up record');
    assertRecord(parsed.record);
    assertDigest(parsed.seal);
    const expectedSeal = this.digest('seal', JSON.stringify(parsed.record));
    if (!equalDigest(parsed.seal, expectedSeal) || !equalDigest(parsed.record.referenceDigest, expectedDigest)) {
      throw new ActionStepUpError('INVALID', 'Invalid step-up seal');
    }
    return parsed.record;
  }

  private async write(record: StepUpRecord): Promise<void> {
    assertRecord(record);
    const envelope: Envelope = { version: 1, record, seal: this.digest('seal', JSON.stringify(record)) };
    const filename = this.filename(record.referenceDigest);
    const temporary = `${filename}.${randomBytes(12).toString('hex')}.tmp`;
    try {
      const handle = await fs.open(temporary, 'wx', 0o600);
      try { await handle.writeFile(JSON.stringify(envelope)); await handle.sync(); }
      finally { await handle.close(); }
      await fs.rename(temporary, filename);
      await this.syncDirectory();
    } catch {
      await fs.unlink(temporary).catch(() => undefined);
      // A rename may already have happened. The next queued operation cannot
      // read it until prepare() durably syncs the containing directory.
      throw new ActionStepUpError('UNAVAILABLE', 'Step-up publication is unavailable');
    }
  }

  private async pruneExpired(): Promise<number> {
    let entries: string[];
    try { entries = await fs.readdir(this.directory); }
    catch { throw new ActionStepUpError('UNAVAILABLE', 'Step-up storage is unavailable'); }
    let removed = false;
    let live = 0;
    for (const entry of entries) {
      if (/^[a-f0-9]{64}\.json\.[a-f0-9]{24}\.tmp$/.test(entry)) {
        // A crashed, unpublished temporary has no authority. Remove only
        // after every possible challenge carried by it has expired.
        const temporary = path.join(this.directory, entry);
        const state = await fs.stat(temporary).catch(() => {
          throw new ActionStepUpError('UNAVAILABLE', 'Step-up storage is unavailable');
        });
        if (state.mtimeMs <= this.clock() - MAX_TTL_MS) {
          await fs.unlink(temporary).catch(() => {
            throw new ActionStepUpError('UNAVAILABLE', 'Step-up storage is unavailable');
          });
          removed = true;
        }
        continue;
      }
      if (!entry.endsWith('.json')) continue;
      if (!/^[a-f0-9]{64}\.json$/.test(entry)) throw new ActionStepUpError('INVALID', 'Invalid step-up filename');
      // No raw reference is needed to validate a sealed record during pruning.
      const raw = await fs.readFile(path.join(this.directory, entry), 'utf8').catch(() => {
        throw new ActionStepUpError('UNAVAILABLE', 'Step-up storage is unavailable');
      });
      let envelope: unknown;
      try { envelope = JSON.parse(raw); } catch { throw new ActionStepUpError('INVALID', 'Invalid step-up record'); }
      assertKeys(envelope, ['version', 'record', 'seal']);
      if (envelope.version !== 1) throw new ActionStepUpError('INVALID', 'Unsupported step-up record');
      assertRecord(envelope.record);
      assertDigest(envelope.seal);
      if (entry !== `${envelope.record.referenceDigest}.json` ||
          !equalDigest(envelope.seal, this.digest('seal', JSON.stringify(envelope.record)))) {
        throw new ActionStepUpError('INVALID', 'Invalid step-up seal');
      }
      if (envelope.record.expiresAt <= this.clock()) {
        await fs.unlink(path.join(this.directory, entry)).catch(() => {
          throw new ActionStepUpError('UNAVAILABLE', 'Step-up storage is unavailable');
        });
        removed = true;
      } else live++;
    }
    if (removed) {
      try { await this.syncDirectory(); }
      catch { throw new ActionStepUpError('UNAVAILABLE', 'Step-up cleanup is unavailable'); }
    }
    return live;
  }

  private assertLive(record: StepUpRecord): void {
    const now = this.clock();
    if (now < record.createdAt || now >= record.expiresAt) throw new ActionStepUpError('EXPIRED', 'Step-up permit expired');
  }

  private assertIdentityMatch(record: StepUpRecord, identity: ActionStepUpIdentity): void {
    if (!equalDigest(record.identityDigest, this.digest('identity', JSON.stringify(identityValues(identity)))) ||
        !equalDigest(record.userDigest, this.digest('user', identity.userId)) ||
        !equalDigest(record.factorBinding, identity.factorBinding)) {
      throw new ActionStepUpError('UNAUTHORIZED', 'Step-up principal or factor changed');
    }
  }

  private assertBindingMatch(record: StepUpRecord, binding: ActionStepUpBinding): void {
    this.assertIdentityMatch(record, binding);
    if (!equalDigest(record.bindingDigest, this.digest('binding', JSON.stringify(bindingValues(binding)))) ||
        record.action !== binding.action || record.resourceKind !== binding.resourceKind ||
        !equalDigest(record.resourceDigest, this.digest('resource', binding.resourceId)) ||
        !equalDigest(record.intentDigest, binding.intentDigest) ||
        !equalDigest(record.targetDigest, binding.targetDigest)) {
      throw new ActionStepUpError('UNAUTHORIZED', 'Step-up action or intent changed');
    }
  }
}
