import type { BackupCodeSet } from '../../types/auth.js';
import {
  FirstUserBootstrapConflictError,
  cloneBootstrapValue,
  firstUserBootstrapMaterialDigest,
  firstUserBootstrapPendingAttemptMaterialDigest,
  type FirstUserBootstrapFinalization,
} from '../../storage/firstUserBootstrap.js';

/** Server-held bootstrap material. Never serialize this into client state. */
export interface BootstrapPendingAttempt {
  version: 1;
  tenantId: string;
  attemptId: string;
  actorId: string;
  handle: string;
  displayName: string;
  email?: string;
  passwordHash: string;
  totpSecret: string;
  backupCodes: string[];
  backupCodeSet: BackupCodeSet;
  createdAt: string;
  expiresAt: string;
  profile?: BootstrapProfile;
  finalization?: FirstUserBootstrapFinalization;
}

export interface BootstrapProfile {
  bio?: string;
  pronouns?: string;
  avatarUrl?: string;
}

/** Server-side custody with compare-and-set finalization preparation. */
export interface BootstrapAttemptStore {
  create(attempt: BootstrapPendingAttempt): Promise<void>;
  get(
    tenantId: string,
    attemptId: string,
  ): Promise<BootstrapPendingAttempt | null>;
  getActiveForTenant(tenantId: string): Promise<BootstrapPendingAttempt | null>;
  updateProfile(
    tenantId: string,
    attemptId: string,
    profile: BootstrapProfile,
  ): Promise<BootstrapPendingAttempt>;
  prepareFinalization(
    tenantId: string,
    attemptId: string,
    expectedAttemptDigest: string,
    finalization: FirstUserBootstrapFinalization,
  ): Promise<BootstrapPendingAttempt>;
  delete(tenantId: string, attemptId: string): Promise<boolean>;
}

function attemptKey(tenantId: string, attemptId: string): string {
  return `${tenantId}\0${attemptId}`;
}

export function bootstrapPendingAttemptDigest(
  attempt: BootstrapPendingAttempt,
): string {
  const { finalization: _finalization, ...mutableAttempt } = attempt;
  return firstUserBootstrapPendingAttemptMaterialDigest(
    attempt.tenantId,
    attempt.attemptId,
    mutableAttempt,
  );
}

/** Single-process custody. Multi-replica consumers need a durable CAS store. */
export class MemoryBootstrapAttemptStore implements BootstrapAttemptStore {
  private readonly attempts = new Map<string, BootstrapPendingAttempt>();

  constructor(private readonly now: () => Date = () => new Date()) {}

  private findLiveAttempt(
    tenantId: string,
    attemptId: string,
  ): BootstrapPendingAttempt | null {
    const key = attemptKey(tenantId, attemptId);
    const attempt = this.attempts.get(key);
    if (!attempt) return null;
    if (this.now().getTime() > Date.parse(attempt.expiresAt)) {
      this.attempts.delete(key);
      return null;
    }
    return attempt;
  }

  private findActiveForTenant(
    tenantId: string,
  ): BootstrapPendingAttempt | null {
    const nowMs = this.now().getTime();
    for (const [key, attempt] of this.attempts) {
      if (attempt.tenantId !== tenantId) continue;
      if (Date.parse(attempt.expiresAt) < nowMs) {
        this.attempts.delete(key);
        continue;
      }
      return attempt;
    }
    return null;
  }

  async create(attempt: BootstrapPendingAttempt): Promise<void> {
    // Keep the check and insertion in one synchronous turn. Awaiting the
    // public lookup here would let two concurrent callers both observe null.
    if (this.findActiveForTenant(attempt.tenantId)) {
      throw new FirstUserBootstrapConflictError(
        'A bootstrap attempt is already active for this tenant',
      );
    }
    const key = attemptKey(attempt.tenantId, attempt.attemptId);
    if (this.attempts.has(key)) {
      throw new FirstUserBootstrapConflictError('Bootstrap attempt already exists');
    }
    this.attempts.set(key, cloneBootstrapValue(attempt));
  }

  async get(
    tenantId: string,
    attemptId: string,
  ): Promise<BootstrapPendingAttempt | null> {
    const attempt = this.findLiveAttempt(tenantId, attemptId);
    return attempt ? cloneBootstrapValue(attempt) : null;
  }

  async getActiveForTenant(
    tenantId: string,
  ): Promise<BootstrapPendingAttempt | null> {
    const attempt = this.findActiveForTenant(tenantId);
    return attempt ? cloneBootstrapValue(attempt) : null;
  }

  async updateProfile(
    tenantId: string,
    attemptId: string,
    profile: BootstrapProfile,
  ): Promise<BootstrapPendingAttempt> {
    const key = attemptKey(tenantId, attemptId);
    const attempt = this.findLiveAttempt(tenantId, attemptId);
    if (!attempt) {
      throw new FirstUserBootstrapConflictError(
        'Bootstrap attempt is missing or expired',
      );
    }
    if (attempt.finalization) {
      throw new FirstUserBootstrapConflictError(
        'Bootstrap profile is immutable after finalization is prepared',
      );
    }
    attempt.profile = cloneBootstrapValue(profile);
    this.attempts.set(key, attempt);
    return cloneBootstrapValue(attempt);
  }

  async prepareFinalization(
    tenantId: string,
    attemptId: string,
    expectedAttemptDigest: string,
    finalization: FirstUserBootstrapFinalization,
  ): Promise<BootstrapPendingAttempt> {
    const key = attemptKey(tenantId, attemptId);
    const attempt = this.findLiveAttempt(tenantId, attemptId);
    if (!attempt) {
      throw new FirstUserBootstrapConflictError(
        'Bootstrap attempt is missing or expired',
      );
    }
    if (
      finalization.tenantId !== tenantId ||
      finalization.attemptId !== attemptId
    ) {
      throw new FirstUserBootstrapConflictError(
        'Bootstrap finalization does not match the pending attempt',
      );
    }
    if (!attempt.finalization) {
      if (bootstrapPendingAttemptDigest(attempt) !== expectedAttemptDigest) {
        throw new FirstUserBootstrapConflictError(
          'Bootstrap attempt changed while finalization was being prepared',
        );
      }
      attempt.finalization = cloneBootstrapValue(finalization);
      this.attempts.set(key, attempt);
    }
    return cloneBootstrapValue(attempt);
  }

  async delete(tenantId: string, attemptId: string): Promise<boolean> {
    return this.attempts.delete(attemptKey(tenantId, attemptId));
  }
}

export interface BootstrapAttemptStoreConformanceHarness {
  store: BootstrapAttemptStore;
  now(): Date;
  advanceTime(ms: number): Promise<void>;
  cleanup(): Promise<void>;
}

export type BootstrapAttemptStoreConformanceHarnessFactory =
  () => Promise<BootstrapAttemptStoreConformanceHarness>;

export interface BootstrapAttemptStoreConformanceResult {
  name: string;
  passed: true;
}

export class BootstrapAttemptStoreConformanceError extends Error {
  constructor(
    readonly caseName: string,
    readonly cause: unknown,
  ) {
    super(
      `Bootstrap attempt-store conformance failed: ${caseName}: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    );
    this.name = 'BootstrapAttemptStoreConformanceError';
  }
}

const CONFORMANCE_TENANT = 'bootstrap-attempt-conformance-tenant';

function createConformanceAttempt(
  attemptId: string,
  actorId: string,
  nowMs: number,
): BootstrapPendingAttempt {
  const createdAt = new Date(nowMs).toISOString();
  return {
    version: 1,
    tenantId: CONFORMANCE_TENANT,
    attemptId,
    actorId,
    handle: 'bootstrap_admin',
    displayName: 'Bootstrap Admin',
    passwordHash: `$2b$04$${'A'.repeat(53)}`,
    totpSecret: 'JBSWY3DPEHPK3PXP',
    backupCodes: ['BACKUP-CODE-1'],
    backupCodeSet: {
      userId: actorId,
      generatedAt: createdAt,
      codes: [{ id: 'backup-code-1', hash: 'a'.repeat(64), used: false }],
    },
    createdAt,
    expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
  };
}

function createConformanceFinalization(
  attempt: BootstrapPendingAttempt,
  nowMs: number,
): FirstUserBootstrapFinalization {
  const finalizedAt = new Date(nowMs).toISOString();
  return {
    version: 1,
    tenantId: attempt.tenantId,
    attemptId: attempt.attemptId,
    finalizedAt,
    user: {
      id: attempt.actorId,
      handle: attempt.handle,
      displayName: attempt.displayName,
      passwordHash: attempt.passwordHash,
      role: 'super_admin',
      isActive: true,
      totpEnabled: true,
      totpSecretId: attempt.handle,
      needsOnboarding: false,
      onboardingStep: 0,
      createdAt: attempt.createdAt,
      updatedAt: finalizedAt,
      ...(attempt.profile?.bio !== undefined ? { bio: attempt.profile.bio } : {}),
    },
    totpSecret: {
      userId: attempt.actorId,
      handle: attempt.handle,
      encryptedSecret: 'conformance-encrypted-totp',
      iv: 'conformance-iv',
      authTag: 'conformance-auth-tag',
      salt: 'conformance-salt',
      createdAt: finalizedAt,
      backupCodesGenerated: true,
      version: 1,
    },
    backupCodes: cloneBootstrapValue(attempt.backupCodeSet),
  };
}

async function runAttemptStoreCase(
  name: string,
  createHarness: BootstrapAttemptStoreConformanceHarnessFactory,
  test: (
    store: BootstrapAttemptStore,
    clock: BootstrapAttemptStoreConformanceClock,
  ) => Promise<void>,
): Promise<BootstrapAttemptStoreConformanceResult> {
  const harness = await createHarness();
  try {
    await test(harness.store, {
      nowMs: () => harnessNowMs(harness),
      advanceTime: (ms) => advanceHarnessTime(harness, ms),
    });
    return { name, passed: true };
  } catch (error) {
    throw new BootstrapAttemptStoreConformanceError(name, error);
  } finally {
    await harness.cleanup();
  }
}

interface BootstrapAttemptStoreConformanceClock {
  nowMs(): number;
  advanceTime(ms: number): Promise<void>;
}

function harnessNowMs(harness: BootstrapAttemptStoreConformanceHarness): number {
  const nowMs = harness.now().getTime();
  if (!Number.isSafeInteger(nowMs)) {
    throw new Error('Attempt-store harness clock returned an invalid date');
  }
  return nowMs;
}

async function advanceHarnessTime(
  harness: BootstrapAttemptStoreConformanceHarness,
  ms: number,
): Promise<void> {
  if (!Number.isSafeInteger(ms) || ms < 0) {
    throw new Error('Attempt-store clock advance must be a non-negative integer');
  }
  const before = harnessNowMs(harness);
  await harness.advanceTime(ms);
  if (harnessNowMs(harness) !== before + ms) {
    throw new Error(`Attempt-store harness clock did not advance by exactly ${ms} ms`);
  }
}

function assertConformance(
  condition: unknown,
  message: string,
): asserts condition {
  if (!condition) throw new Error(message);
}

async function rejects(operation: () => Promise<unknown>): Promise<boolean> {
  try {
    await operation();
    return false;
  } catch {
    return true;
  }
}

/** Framework-neutral CAS/replay contract for durable bootstrap attempt stores. */
export async function runBootstrapAttemptStoreConformance(
  createHarness: BootstrapAttemptStoreConformanceHarnessFactory,
): Promise<BootstrapAttemptStoreConformanceResult[]> {
  return Promise.all([
    runAttemptStoreCase('one active attempt per tenant', createHarness, async (store, clock) => {
      const nowMs = clock.nowMs();
      const outcomes = await Promise.allSettled([
        store.create(createConformanceAttempt(
          'conformance-attempt-identifier-0001',
          'conformance-actor-0001',
          nowMs,
        )),
        store.create(createConformanceAttempt(
          'conformance-attempt-identifier-0002',
          'conformance-actor-0002',
          nowMs,
        )),
      ]);
      assertConformance(
        outcomes.filter((outcome) => outcome.status === 'fulfilled').length === 1,
        'expected exactly one successful create',
      );
    }),
    runAttemptStoreCase('returned attempts are detached', createHarness, async (store, clock) => {
      const attempt = createConformanceAttempt(
        'conformance-attempt-identifier-0003',
        'conformance-actor-0003',
        clock.nowMs(),
      );
      await store.create(attempt);
      const returned = await store.get(attempt.tenantId, attempt.attemptId);
      assertConformance(returned !== null, 'created attempt is missing');
      returned.passwordHash = 'mutated';
      returned.backupCodes[0] = 'mutated';
      const persisted = await store.get(attempt.tenantId, attempt.attemptId);
      assertConformance(
        persisted?.passwordHash === attempt.passwordHash &&
          persisted.backupCodes[0] === attempt.backupCodes[0],
        'returned attempt mutated server custody',
      );
    }),
    runAttemptStoreCase('stale profile snapshots conflict', createHarness, async (store, clock) => {
      const attempt = createConformanceAttempt(
        'conformance-attempt-identifier-0004',
        'conformance-actor-0004',
        clock.nowMs(),
      );
      await store.create(attempt);
      const stale = await store.get(attempt.tenantId, attempt.attemptId);
      assertConformance(stale !== null, 'created attempt is missing');
      await store.updateProfile(attempt.tenantId, attempt.attemptId, {
        bio: 'Latest profile',
      });
      assertConformance(
        await rejects(() => store.prepareFinalization(
          attempt.tenantId,
          attempt.attemptId,
          bootstrapPendingAttemptDigest(stale),
          createConformanceFinalization(stale, clock.nowMs()),
        )),
        'stale finalization was accepted',
      );
      const current = await store.get(attempt.tenantId, attempt.attemptId);
      assertConformance(current !== null, 'updated attempt is missing');
      const prepared = await store.prepareFinalization(
        attempt.tenantId,
        attempt.attemptId,
        bootstrapPendingAttemptDigest(current),
        createConformanceFinalization(current, clock.nowMs()),
      );
      assertConformance(
        prepared.finalization?.user.bio === 'Latest profile',
        'current profile was not retained in finalization',
      );
    }),
    runAttemptStoreCase('concurrent exact preparation is idempotent', createHarness, async (store, clock) => {
      const attempt = createConformanceAttempt(
        'conformance-attempt-identifier-0005',
        'conformance-actor-0005',
        clock.nowMs(),
      );
      await store.create(attempt);
      const current = await store.get(attempt.tenantId, attempt.attemptId);
      assertConformance(current !== null, 'created attempt is missing');
      const digest = bootstrapPendingAttemptDigest(current);
      const finalization = createConformanceFinalization(current, clock.nowMs());
      const prepared = await Promise.all([
        store.prepareFinalization(
          attempt.tenantId,
          attempt.attemptId,
          digest,
          finalization,
        ),
        store.prepareFinalization(
          attempt.tenantId,
          attempt.attemptId,
          digest,
          finalization,
        ),
      ]);
      const firstPrepared = prepared[0].finalization;
      const secondPrepared = prepared[1].finalization;
      assertConformance(
        firstPrepared !== undefined && secondPrepared !== undefined,
        'concurrent preparation did not retain finalized authority',
      );
      assertConformance(
        firstUserBootstrapMaterialDigest(firstPrepared) ===
          firstUserBootstrapMaterialDigest(secondPrepared),
        'concurrent preparation returned different authority',
      );
    }),
    runAttemptStoreCase('prepared attempts expire and permit replacement', createHarness, async (store, clock) => {
      const startedAt = clock.nowMs();
      const attempt = createConformanceAttempt(
        'conformance-attempt-identifier-0006',
        'conformance-actor-0006',
        startedAt,
      );
      attempt.createdAt = new Date(startedAt).toISOString();
      attempt.expiresAt = new Date(startedAt + 5 * 60 * 1000).toISOString();
      await store.create(attempt);
      const current = await store.get(attempt.tenantId, attempt.attemptId);
      assertConformance(current !== null, 'live attempt is missing');
      await store.prepareFinalization(
        attempt.tenantId,
        attempt.attemptId,
        bootstrapPendingAttemptDigest(current),
        createConformanceFinalization(current, clock.nowMs()),
      );
      await clock.advanceTime(6 * 60 * 1000);
      assertConformance(
        (await store.get(attempt.tenantId, attempt.attemptId)) === null,
        'expired prepared attempt remained readable',
      );
      assertConformance(
        (await store.getActiveForTenant(attempt.tenantId)) === null,
        'expired prepared attempt remained active',
      );
      assertConformance(
        await rejects(() => store.prepareFinalization(
          attempt.tenantId,
          attempt.attemptId,
          bootstrapPendingAttemptDigest(current),
          createConformanceFinalization(current, clock.nowMs()),
        )),
        'expired prepared attempt accepted another finalization',
      );
      const replacement = createConformanceAttempt(
        'conformance-attempt-identifier-0010',
        'conformance-actor-0010',
        clock.nowMs(),
      );
      replacement.createdAt = new Date(startedAt + 6 * 60 * 1000).toISOString();
      replacement.expiresAt = new Date(startedAt + 11 * 60 * 1000).toISOString();
      await store.create(replacement);
      assertConformance(
        (await store.getActiveForTenant(replacement.tenantId))?.attemptId ===
          replacement.attemptId,
        'replacement attempt did not become active after expiry',
      );
    }),
    runAttemptStoreCase('attempt lifetime includes the exact expiry boundary', createHarness, async (store, clock) => {
      const startedAt = clock.nowMs();
      const keyedAttempt = createConformanceAttempt(
        'conformance-attempt-identifier-0011',
        'conformance-actor-0011',
        startedAt,
      );
      keyedAttempt.tenantId = `${CONFORMANCE_TENANT}-keyed`;
      keyedAttempt.createdAt = new Date(startedAt).toISOString();
      keyedAttempt.expiresAt = new Date(startedAt + 600_000).toISOString();
      const activeAttempt = createConformanceAttempt(
        'conformance-attempt-identifier-0012',
        'conformance-actor-0012',
        startedAt,
      );
      activeAttempt.tenantId = `${CONFORMANCE_TENANT}-active`;
      activeAttempt.createdAt = new Date(startedAt).toISOString();
      activeAttempt.expiresAt = new Date(startedAt + 600_000).toISOString();
      await store.create(keyedAttempt);
      await store.create(activeAttempt);

      await clock.advanceTime(599_999);
      assertConformance(
        (await store.get(keyedAttempt.tenantId, keyedAttempt.attemptId)) !== null,
        'attempt expired at 599999 ms',
      );
      assertConformance(
        (await store.getActiveForTenant(activeAttempt.tenantId)) !== null,
        'active attempt expired at 599999 ms',
      );

      await clock.advanceTime(1);
      assertConformance(
        (await store.get(keyedAttempt.tenantId, keyedAttempt.attemptId)) !== null,
        'attempt expired at the exact 600000 ms boundary',
      );
      assertConformance(
        (await store.getActiveForTenant(activeAttempt.tenantId)) !== null,
        'active attempt expired at the exact 600000 ms boundary',
      );

      await clock.advanceTime(1);
      assertConformance(
        (await store.get(keyedAttempt.tenantId, keyedAttempt.attemptId)) === null,
        'attempt remained readable at 600001 ms',
      );
      assertConformance(
        (await store.getActiveForTenant(activeAttempt.tenantId)) === null,
        'attempt remained active at 600001 ms',
      );
    }),
    runAttemptStoreCase('delete removes pending credentials', createHarness, async (store, clock) => {
      const attempt = createConformanceAttempt(
        'conformance-attempt-identifier-0007',
        'conformance-actor-0007',
        clock.nowMs(),
      );
      await store.create(attempt);
      assertConformance(
        await store.delete(attempt.tenantId, attempt.attemptId),
        'existing attempt was not deleted',
      );
      assertConformance(
        (await store.get(attempt.tenantId, attempt.attemptId)) === null,
        'deleted credentials remained readable',
      );
      assertConformance(
        !(await store.delete(attempt.tenantId, attempt.attemptId)),
        'second delete reported a credential record',
      );
    }),
    runAttemptStoreCase('prepared attempts reject later mutation', createHarness, async (store, clock) => {
      const attempt = createConformanceAttempt(
        'conformance-attempt-identifier-0008',
        'conformance-actor-0008',
        clock.nowMs(),
      );
      await store.create(attempt);
      const current = await store.get(attempt.tenantId, attempt.attemptId);
      assertConformance(current !== null, 'created attempt is missing');
      await store.prepareFinalization(
        attempt.tenantId,
        attempt.attemptId,
        bootstrapPendingAttemptDigest(current),
        createConformanceFinalization(current, clock.nowMs()),
      );
      assertConformance(
        await rejects(() => store.updateProfile(
          attempt.tenantId,
          attempt.attemptId,
          { bio: 'Too late' },
        )),
        'prepared attempt accepted mutable profile data',
      );
    }),
    runAttemptStoreCase('concurrent different preparation converges', createHarness, async (store, clock) => {
      const attempt = createConformanceAttempt(
        'conformance-attempt-identifier-0009',
        'conformance-actor-0009',
        clock.nowMs(),
      );
      await store.create(attempt);
      const current = await store.get(attempt.tenantId, attempt.attemptId);
      assertConformance(current !== null, 'created attempt is missing');
      const digest = bootstrapPendingAttemptDigest(current);
      const first = createConformanceFinalization(current, clock.nowMs());
      const second = cloneBootstrapValue(first);
      second.user.displayName = 'Different Finalization';
      const prepared = await Promise.all([
        store.prepareFinalization(
          attempt.tenantId,
          attempt.attemptId,
          digest,
          first,
        ),
        store.prepareFinalization(
          attempt.tenantId,
          attempt.attemptId,
          digest,
          second,
        ),
      ]);
      const firstPrepared = prepared[0].finalization;
      const secondPrepared = prepared[1].finalization;
      assertConformance(
        firstPrepared !== undefined && secondPrepared !== undefined,
        'concurrent preparation did not retain finalized authority',
      );
      assertConformance(
        firstUserBootstrapMaterialDigest(firstPrepared) ===
          firstUserBootstrapMaterialDigest(secondPrepared),
        'concurrent different finalization did not converge on one winner',
      );
    }),
  ]);
}
