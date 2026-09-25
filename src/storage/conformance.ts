import { createHash, randomUUID } from 'crypto';
import type { IStorageAdapter } from './interface.js';
import {
  FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS,
  canonicalizeFirstUserBootstrapClaimResult,
  canonicalizeFirstUserBootstrapFinalizationPayload,
  cloneBootstrapValue,
  firstUserBootstrapMaterialDigest,
  firstUserBootstrapValueDigest,
  normalizeFirstUserBootstrapTenantId,
  parseFirstUserBootstrapReceipt,
  parseFirstUserBootstrapReceiptForTenant,
  type FirstUserBootstrapFinalization,
  type FirstUserBootstrapReceipt,
  type FirstUserBootstrapReceiptExpectation,
  type InertFirstUserClaim,
} from './firstUserBootstrap.js';

const SYNTHETIC_BCRYPT_HASH = `$2b$04$${'A'.repeat(53)}`;

type AdminUserWithUnknown = FirstUserBootstrapFinalization['user'] & {
  password?: string;
};

function cloneFinalization(
  value: FirstUserBootstrapFinalization,
): FirstUserBootstrapFinalization {
  return cloneBootstrapValue(value);
}

export interface FirstUserBootstrapConformanceHarness {
  storage: IStorageAdapter;
  now(): Date;
  advanceTime(ms: number): Promise<void>;
  cleanup(): Promise<void>;
}

export type FirstUserBootstrapConformanceHarnessFactory =
  (tenantId: string) => Promise<FirstUserBootstrapConformanceHarness>;

export interface FirstUserBootstrapConformanceResult {
  name: string;
  passed: true;
}

export class FirstUserBootstrapConformanceError extends Error {
  constructor(
    readonly caseName: string,
    readonly cause: unknown,
  ) {
    super(
      `First-user bootstrap storage conformance failed: ${caseName}: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    );
    this.name = 'FirstUserBootstrapConformanceError';
  }
}

function assert(condition: unknown, message: string): asserts condition {
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

async function claimBootstrap(
  storage: IStorageAdapter,
  claim: InertFirstUserClaim,
): Promise<InertFirstUserClaim> {
  const returned = await storage.claimFirstUserBootstrap(claim);
  return canonicalizeFirstUserBootstrapClaimResult(returned, claim);
}

async function finalizeBootstrap(
  storage: IStorageAdapter,
  claim: InertFirstUserClaim,
  finalization: FirstUserBootstrapFinalization,
): Promise<FirstUserBootstrapReceipt> {
  const canonicalFinalization =
    canonicalizeFirstUserBootstrapFinalizationPayload(finalization);
  const returned = await storage.finalizeFirstUserBootstrap(canonicalFinalization);
  return parseFirstUserBootstrapReceipt(returned, {
    claim,
    finalization: canonicalFinalization,
  });
}

async function readBootstrapReceipt(
  storage: IStorageAdapter,
  tenantId: string,
  expected?: FirstUserBootstrapReceiptExpectation,
): Promise<FirstUserBootstrapReceipt | null> {
  const canonicalTenantId = normalizeFirstUserBootstrapTenantId(tenantId);
  const returned = await storage.getFirstUserBootstrapReceipt(canonicalTenantId);
  if (returned === null) return null;
  const receipt = expected
    ? parseFirstUserBootstrapReceipt(returned, expected)
    : parseFirstUserBootstrapReceiptForTenant(returned, canonicalTenantId);
  assert(
    receipt.tenantId === canonicalTenantId,
    'storage returned a bootstrap receipt for a different tenant',
  );
  return receipt;
}

function syntheticHash(label: string): string {
  return createHash('sha256').update(`synthetic-${label}`).digest('hex');
}

function createMaterial(
  tenantId: string,
  claimedAtMs: number,
  finalizedAtMs: number = claimedAtMs,
): {
  claim: InertFirstUserClaim;
  finalization: FirstUserBootstrapFinalization;
} {
  const claimedAt = new Date(claimedAtMs).toISOString();
  const userId = randomUUID();
  const claim: InertFirstUserClaim = {
    version: 1,
    tenantId,
    attemptId: randomUUID(),
    actor: {
      id: userId,
      handle: `bootstrap_${userId.slice(0, 8)}`,
      isActive: false,
      totpEnabled: false,
      sessionAuthority: false,
      backupCodesGenerated: false,
    },
    claimedAt,
  };
  const finalizedAt = new Date(finalizedAtMs).toISOString();
  return {
    claim,
    finalization: {
      version: 1,
      tenantId,
      attemptId: claim.attemptId,
      finalizedAt,
      user: {
        id: userId,
        handle: claim.actor.handle,
        passwordHash: SYNTHETIC_BCRYPT_HASH,
        totpEnabled: true,
        totpSecretId: claim.actor.handle,
        role: 'super_admin',
        isActive: true,
        needsOnboarding: false,
        onboardingStep: 0,
        createdAt: claimedAt,
        updatedAt: finalizedAt,
      },
      totpSecret: {
        userId,
        handle: claim.actor.handle,
        encryptedSecret: 'synthetic-encrypted-totp',
        iv: 'synthetic-iv',
        authTag: 'synthetic-auth-tag',
        salt: 'synthetic-salt',
        createdAt: finalizedAt,
        backupCodesGenerated: true,
        version: 1,
      },
      backupCodes: {
        userId,
        generatedAt: finalizedAt,
        codes: [
          { id: randomUUID(), hash: syntheticHash('one'), used: false },
          { id: randomUUID(), hash: syntheticHash('two'), used: false },
        ],
      },
    },
  };
}

function createOrdinaryUser(
  handle: string,
  nowMs: number,
): Omit<FirstUserBootstrapFinalization['user'], 'id'> {
  const timestamp = new Date(nowMs).toISOString();
  return {
    handle,
    passwordHash: SYNTHETIC_BCRYPT_HASH,
    totpEnabled: false,
    role: 'member',
    isActive: true,
    needsOnboarding: false,
    onboardingStep: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

interface FirstUserBootstrapConformanceClock {
  nowMs(): number;
  advanceTime(ms: number): Promise<void>;
}

function harnessNowMs(harness: FirstUserBootstrapConformanceHarness): number {
  const nowMs = harness.now().getTime();
  assert(Number.isSafeInteger(nowMs), 'harness clock returned an invalid date');
  return nowMs;
}

async function advanceHarnessTime(
  harness: FirstUserBootstrapConformanceHarness,
  ms: number,
): Promise<void> {
  assert(Number.isSafeInteger(ms) && ms >= 0, 'clock advance must be a non-negative integer');
  const before = harnessNowMs(harness);
  await harness.advanceTime(ms);
  assert(
    harnessNowMs(harness) === before + ms,
    `harness clock did not advance by exactly ${ms} ms`,
  );
}

function runCase(
  name: string,
  createHarness: FirstUserBootstrapConformanceHarnessFactory,
  test: (
    storage: IStorageAdapter,
    tenantId: string,
    clock: FirstUserBootstrapConformanceClock,
  ) => Promise<void>,
): () => Promise<FirstUserBootstrapConformanceResult> {
  return async () => {
    const tenantId = randomUUID();
    const harness = await createHarness(tenantId);
    try {
      await harness.storage.init();
      await test(harness.storage, tenantId, {
        nowMs: () => harnessNowMs(harness),
        advanceTime: (ms) => advanceHarnessTime(harness, ms),
      });
      return { name, passed: true };
    } catch (error) {
      throw new FirstUserBootstrapConformanceError(name, error);
    } finally {
      try {
        await harness.storage.close();
      } finally {
        await harness.cleanup();
      }
    }
  };
}

/**
 * Framework-neutral backend contract runner. It certifies claim/finalize and
 * the transactionally receipt-gated ordinary `createUser` boundary. PG/Redis
 * adapters can invoke it from any test framework by supplying a fresh,
 * isolated tenant/store harness.
 */
export async function runFirstUserBootstrapStorageConformance(
  createHarness: FirstUserBootstrapConformanceHarnessFactory,
): Promise<FirstUserBootstrapConformanceResult[]> {
  const cases: Array<() => Promise<FirstUserBootstrapConformanceResult>> = [];

  cases.push(runCase('concurrent claims have one winner', createHarness, async (storage, tenantId, clock) => {
    const nowMs = clock.nowMs();
    const first = createMaterial(tenantId, nowMs).claim;
    const second = createMaterial(tenantId, nowMs).claim;
    const outcomes = await Promise.allSettled([
      claimBootstrap(storage, first),
      claimBootstrap(storage, second),
    ]);
    assert(
      outcomes.filter((outcome) => outcome.status === 'fulfilled').length === 1,
      'expected exactly one successful claim',
    );
  }));

  cases.push(runCase('ordinary creation cannot create the first user', createHarness, async (storage, tenantId, clock) => {
    const ordinary = createOrdinaryUser('ordinary_first_user', clock.nowMs());
    assert(
      await rejects(() => storage.createUser(ordinary)),
      'ordinary createUser inserted the first user without bootstrap finalization',
    );
    assert(!(await storage.hasUsers()), 'rejected ordinary creation left a user behind');
    assert(
      (await readBootstrapReceipt(storage, tenantId)) === null,
      'rejected ordinary creation forged a bootstrap receipt',
    );
  }));

  cases.push(runCase('active or credentialed claims are rejected', createHarness, async (storage, tenantId, clock) => {
    const nowMs = clock.nowMs();
    const active = createMaterial(tenantId, nowMs).claim;
    (active.actor as { isActive: boolean }).isActive = true;
    assert(
      await rejects(() => storage.claimFirstUserBootstrap(active)),
      'active claim was accepted',
    );

    const credentialed = createMaterial(tenantId, nowMs).claim;
    (credentialed.actor as unknown as { passwordHash: string }).passwordHash =
      SYNTHETIC_BCRYPT_HASH;
    assert(
      await rejects(() => storage.claimFirstUserBootstrap(credentialed)),
      'credentialed claim was accepted',
    );
  }));

  cases.push(runCase('claim schemas are exact and rejection leaves no claim', createHarness, async (storage, tenantId, clock) => {
    const nowMs = clock.nowMs();
    const unknown = createMaterial(tenantId, nowMs).claim as InertFirstUserClaim & {
      credentials?: { passwordHash: string };
    };
    unknown.credentials = { passwordHash: SYNTHETIC_BCRYPT_HASH };
    assert(
      await rejects(() => storage.claimFirstUserBootstrap(unknown)),
      'claim with an unknown credential alias was accepted',
    );

    const missing = createMaterial(tenantId, nowMs).claim;
    Reflect.deleteProperty(
      missing as unknown as Record<string, unknown>,
      'claimedAt',
    );
    assert(
      await rejects(() => storage.claimFirstUserBootstrap(missing as InertFirstUserClaim)),
      'claim with a missing required field was accepted',
    );

    const valid = createMaterial(tenantId, nowMs).claim;
    await claimBootstrap(storage, valid);
    assert(!(await storage.hasUsers()), 'rejected claim material created authority');
  }));

  cases.push(runCase('claim timestamps are bound and expired inputs are rejected', createHarness, async (storage, tenantId, clock) => {
    const nowMs = clock.nowMs();
    const expired = createMaterial(tenantId, nowMs).claim;
    expired.claimedAt = new Date(
      nowMs - FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS - 1,
    ).toISOString();
    assert(
      await rejects(() => storage.claimFirstUserBootstrap(expired)),
      'claim older than the fixed ten-minute lifetime was accepted',
    );

    const fresh = createMaterial(tenantId, nowMs).claim;
    const returned = await claimBootstrap(storage, fresh);
    assert(
      returned.claimedAt === fresh.claimedAt,
      'storage changed claimedAt while accepting a bootstrap claim',
    );
  }));

  cases.push(runCase('finalization succeeds at 599999 ms', createHarness, async (storage, tenantId, clock) => {
    assert(
      FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS === 600_000,
      'first-user claim lifetime is not ten minutes',
    );
    const startedAt = clock.nowMs();
    const { claim, finalization } = createMaterial(
      tenantId,
      startedAt,
      startedAt + 599_999,
    );
    await claimBootstrap(storage, claim);
    await clock.advanceTime(599_999);
    await finalizeBootstrap(storage, claim, finalization);
  }));

  cases.push(runCase('finalization succeeds at 600000 ms', createHarness, async (storage, tenantId, clock) => {
    const startedAt = clock.nowMs();
    const { claim, finalization } = createMaterial(
      tenantId,
      startedAt,
      startedAt + FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS,
    );
    await claimBootstrap(storage, claim);
    await clock.advanceTime(FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS);
    await finalizeBootstrap(storage, claim, finalization);
  }));

  cases.push(runCase('finalization is rejected at 600001 ms', createHarness, async (storage, tenantId, clock) => {
    const startedAt = clock.nowMs();
    const { claim, finalization } = createMaterial(
      tenantId,
      startedAt,
      startedAt + FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS,
    );
    await claimBootstrap(storage, claim);
    await clock.advanceTime(FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS + 1);
    assert(
      await rejects(() => storage.finalizeFirstUserBootstrap(finalization)),
      'finalization was accepted at 600001 ms',
    );
    assert(!(await storage.hasUsers()), 'expired finalization created authority');
    assert(
      (await readBootstrapReceipt(storage, tenantId)) === null,
      'expired finalization persisted a receipt',
    );
  }));

  cases.push(runCase('missing and mismatched claims fail closed', createHarness, async (storage, tenantId, clock) => {
    const original = createMaterial(tenantId, clock.nowMs());
    assert(
      await rejects(() => storage.finalizeFirstUserBootstrap(original.finalization)),
      'finalization without a stored claim was accepted',
    );

    await claimBootstrap(storage, original.claim);
    const competing = createMaterial(tenantId, clock.nowMs());
    assert(
      await rejects(() => storage.finalizeFirstUserBootstrap(competing.finalization)),
      'finalization for a different attempt was accepted',
    );
    assert(!(await storage.hasUsers()), 'failed finalization created authority');
    assert(
      (await readBootstrapReceipt(storage, tenantId)) === null,
      'failed finalization persisted a receipt',
    );
  }));

  cases.push(runCase('canonical digest rejects lossy non-JSON values', createHarness, async () => {
    const accessor = Object.defineProperty({}, 'value', {
      enumerable: true,
      get: () => 'not-data',
    });
    const symbolKey = { value: 'visible' } as Record<PropertyKey, unknown>;
    symbolKey[Symbol('hidden')] = 'not-json';
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    const invalidValues: unknown[] = [
      undefined,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
      -0,
      () => undefined,
      Symbol('bootstrap'),
      1n,
      new Array(1),
      new Date(),
      new Map([['value', 'not-json']]),
      accessor,
      symbolKey,
      cycle,
    ];
    for (const value of invalidValues) {
      let rejected = false;
      try {
        firstUserBootstrapValueDigest(value);
      } catch {
        rejected = true;
      }
      assert(rejected, `digest accepted ${String(value)}`);
    }
    assert(
      firstUserBootstrapValueDigest({ value: 0 }) !==
        firstUserBootstrapValueDigest({ value: null }),
      'distinct canonical JSON values shared a digest input',
    );
  }));

  cases.push(runCase('concurrent exact finalization is idempotent', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    await claimBootstrap(storage, claim);
    const receipts = await Promise.all([
      finalizeBootstrap(storage, claim, finalization),
      finalizeBootstrap(storage, claim, finalization),
    ]);
    assert(
      firstUserBootstrapValueDigest(receipts[0]) ===
        firstUserBootstrapValueDigest(receipts[1]),
      'concurrent exact finalization returned different receipts',
    );
  }));

  cases.push(runCase('concurrent conflicting finalizations have one winner', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    const competing = cloneFinalization(finalization);
    competing.user.displayName = 'Competing Bootstrap Admin';
    await claimBootstrap(storage, claim);

    const outcomes = await Promise.allSettled([
      storage.finalizeFirstUserBootstrap(finalization),
      storage.finalizeFirstUserBootstrap(competing),
    ]);
    assert(
      outcomes.filter((outcome) => outcome.status === 'fulfilled').length === 1,
      'conflicting finalizations did not produce exactly one winner',
    );
    const winner = outcomes[0].status === 'fulfilled' ? finalization : competing;
    const receipt = await readBootstrapReceipt(storage, tenantId);
    assert(
      receipt?.materialDigest === firstUserBootstrapMaterialDigest(winner),
      'immutable receipt does not identify the winning finalization',
    );
    assert(
      (await storage.getUser(claim.actor.id))?.displayName === winner.user.displayName,
      'losing finalization changed the committed first user',
    );
  }));

  cases.push(runCase('claim remains inert', createHarness, async (storage, tenantId, clock) => {
    const { claim } = createMaterial(tenantId, clock.nowMs());
    await claimBootstrap(storage, claim);
    assert(!(await storage.hasUsers()), 'claim created an active user');
    assert(
      await rejects(() =>
        storage.createSession(claim.actor.id, { id: claim.actor.id })),
      'claimed actor received session authority',
    );
  }));

  cases.push(runCase('receipt survives mutable state changes', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    await claimBootstrap(storage, claim);
    const receipt = await finalizeBootstrap(storage, claim, finalization);
    await storage.updateUser(claim.actor.id, { displayName: 'Synthetic Current State' });
    const persisted = await readBootstrapReceipt(storage, claim.tenantId, {
      claim,
      finalization,
    });
    assert(
      persisted !== null &&
        firstUserBootstrapValueDigest(receipt) ===
          firstUserBootstrapValueDigest(persisted),
      'mutable state changed the immutable receipt',
    );
  }));

  cases.push(runCase('invalid material fails before authority exists', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    finalization.user.passwordHash = 'synthetic-invalid-bcrypt';
    await claimBootstrap(storage, claim);
    assert(
      await rejects(() => storage.finalizeFirstUserBootstrap(finalization)),
      'invalid finalization was accepted',
    );
    finalization.user.passwordHash = SYNTHETIC_BCRYPT_HASH;
    finalization.totpSecret.lastUsedTotpStep = 1;
    assert(
      await rejects(() => storage.finalizeFirstUserBootstrap(finalization)),
      'used TOTP factor was accepted',
    );
    delete finalization.totpSecret.lastUsedTotpStep;
    finalization.backupCodes.codes[1].hash = finalization.backupCodes.codes[0].hash;
    assert(
      await rejects(() => storage.finalizeFirstUserBootstrap(finalization)),
      'duplicate backup-code record was accepted',
    );
    assert(!(await storage.hasUsers()), 'invalid finalization created a user');
    assert((await storage.getUser(claim.actor.id)) === null, 'invalid finalization persisted a user');
    assert(
      (await storage.getTOTPSecret(claim.actor.handle)) === null,
      'invalid finalization persisted a TOTP factor',
    );
    assert(
      (await storage.getBackupCodes(claim.actor.id)) === null,
      'invalid finalization persisted backup codes',
    );
    assert(
      (await readBootstrapReceipt(storage, tenantId)) === null,
      'invalid finalization persisted a receipt',
    );
  }));

  cases.push(runCase('finalization schemas are exact before commit and replay', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    await claimBootstrap(storage, claim);

    const malformed: FirstUserBootstrapFinalization[] = [];
    const unknownRoot = cloneFinalization(finalization);
    (unknownRoot as unknown as Record<string, unknown>).credentialAlias =
      'not-allowed';
    malformed.push(unknownRoot);
    const unknown = cloneFinalization(finalization);
    (unknown.user as AdminUserWithUnknown).password = 'credential-alias';
    malformed.push(unknown);
    const missingOnboarding = cloneFinalization(finalization);
    Reflect.deleteProperty(
      missingOnboarding.user as unknown as Record<string, unknown>,
      'needsOnboarding',
    );
    malformed.push(missingOnboarding);
    const undefinedEmail = cloneFinalization(finalization);
    undefinedEmail.user.email = undefined;
    malformed.push(undefinedEmail);
    const nonCanonicalEmail = cloneFinalization(finalization);
    nonCanonicalEmail.user.email = 'BOOTSTRAP@EXAMPLE.COM';
    malformed.push(nonCanonicalEmail);
    const invalidRole = cloneFinalization(finalization);
    invalidRole.user.role = 'admin';
    malformed.push(invalidRole);
    const lockedUser = cloneFinalization(finalization);
    lockedUser.user.isLocked = true;
    malformed.push(lockedUser);
    const negativeZero = cloneFinalization(finalization);
    negativeZero.user.onboardingStep = -0;
    malformed.push(negativeZero);
    const notANumber = cloneFinalization(finalization);
    notANumber.user.onboardingStep = Number.NaN;
    malformed.push(notANumber);
    const infiniteVersion = cloneFinalization(finalization);
    infiniteVersion.totpSecret.version = Number.POSITIVE_INFINITY;
    malformed.push(infiniteVersion);
    const functionValue = cloneFinalization(finalization);
    (functionValue.user as unknown as Record<string, unknown>).displayName =
      () => undefined;
    malformed.push(functionValue);
    const symbolValue = cloneFinalization(finalization);
    (symbolValue.user as unknown as Record<string, unknown>).theme =
      Symbol('theme');
    malformed.push(symbolValue);
    const bigintValue = cloneFinalization(finalization);
    Object.assign(bigintValue.user, {
      githubId: 1n,
      githubLogin: 'bootstrap-admin',
      githubLinkedAt: finalization.finalizedAt,
    });
    malformed.push(bigintValue);
    const sparseCodes = cloneFinalization(finalization);
    sparseCodes.backupCodes.codes = new Array(2);
    malformed.push(sparseCodes);
    const browserEvidence = cloneFinalization(finalization);
    Object.assign(browserEvidence.user as unknown as Record<string, unknown>, {
      browserFingerprint: 'not-bootstrap-authority',
      tempoTraceId: 'not-bootstrap-authority',
    });
    malformed.push(browserEvidence);

    for (const value of malformed) {
      assert(
        await rejects(() => storage.finalizeFirstUserBootstrap(value)),
        'malformed finalization was accepted',
      );
      assert(!(await storage.hasUsers()), 'malformed finalization partially committed a user');
      assert(
        (await storage.getTOTPSecret(claim.actor.handle)) === null &&
          (await storage.getBackupCodes(claim.actor.id)) === null &&
          (await readBootstrapReceipt(storage, tenantId)) === null,
        'malformed finalization partially committed factors or a receipt',
      );
    }

    const receipt = await finalizeBootstrap(storage, claim, finalization);
    const malformedReplay = cloneFinalization(finalization);
    malformedReplay.user.displayName = undefined;
    assert(
      await rejects(() => storage.finalizeFirstUserBootstrap(malformedReplay)),
      'non-JSON completed replay was compared as an exact digest',
    );
    assert(
      firstUserBootstrapValueDigest(
        await readBootstrapReceipt(storage, tenantId, { claim, finalization }),
      ) === firstUserBootstrapValueDigest(receipt),
      'malformed replay changed the immutable receipt',
    );
  }));

  cases.push(runCase('mismatched finalization replay conflicts', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    await claimBootstrap(storage, claim);
    await finalizeBootstrap(storage, claim, finalization);
    finalization.user.displayName = 'Mismatched Synthetic Replay';
    assert(
      await rejects(() => storage.finalizeFirstUserBootstrap(finalization)),
      'mismatched finalization replay was accepted',
    );
  }));

  cases.push(runCase('consumed claims reject new claim authority', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    await claimBootstrap(storage, claim);
    await finalizeBootstrap(storage, claim, finalization);
    assert(
      await rejects(() => storage.claimFirstUserBootstrap(claim)),
      'a finalized claim was accepted as a new claim',
    );
    assert(
      await rejects(() => storage.claimFirstUserBootstrap(
        createMaterial(tenantId, clock.nowMs()).claim,
      )),
      'a competing claim was accepted after finalization',
    );
  }));

  cases.push(runCase('bootstrap actors are deletion-protected', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    await claimBootstrap(storage, claim);
    assert(
      await rejects(() => storage.deleteUser(claim.actor.id)),
      'claimed actor deletion was accepted',
    );
    await finalizeBootstrap(storage, claim, finalization);
    assert(
      await rejects(() => storage.deleteUser(claim.actor.id)),
      'finalized actor deletion was accepted',
    );
  }));

  cases.push(runCase('ordinary creation succeeds after first-user finalization', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    await claimBootstrap(storage, claim);
    await finalizeBootstrap(storage, claim, finalization);
    const user = await storage.createUser(
      createOrdinaryUser(`ordinary_${randomUUID().slice(0, 8)}`, clock.nowMs()),
    );
    assert(user.id !== claim.actor.id, 'ordinary creation replaced the bootstrap actor');
    assert((await storage.getUser(user.id))?.id === user.id, 'ordinary user was not persisted');
  }));

  cases.push(runCase('ordinary creation racing finalization cannot steal first authority', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    await claimBootstrap(storage, claim);
    const ordinary = createOrdinaryUser('racing_ordinary_user', clock.nowMs());
    const [ordinaryOutcome, finalizationOutcome] = await Promise.allSettled([
      storage.createUser(ordinary),
      finalizeBootstrap(storage, claim, finalization),
    ]);

    assert(finalizationOutcome.status === 'fulfilled', 'ordinary creation prevented bootstrap finalization');
    assert((await storage.getUser(claim.actor.id))?.role === 'super_admin', 'bootstrap actor did not win first authority');
    assert(
      (await readBootstrapReceipt(storage, tenantId, { claim, finalization })) !== null,
      'bootstrap race completed without its immutable receipt',
    );
    const persistedOrdinary = await storage.getUserByHandle(ordinary.handle);
    if (ordinaryOutcome.status === 'fulfilled') {
      assert(
        persistedOrdinary?.id === ordinaryOutcome.value.id,
        'successful post-bootstrap ordinary creation was not persisted',
      );
    } else {
      assert(persistedOrdinary === null, 'rejected racing ordinary user was partially persisted');
    }
  }));

  cases.push(runCase('ordinary user deletion revokes sessions', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    await claimBootstrap(storage, claim);
    await finalizeBootstrap(storage, claim, finalization);
    const user = await storage.createUser(
      createOrdinaryUser(`ordinary_${randomUUID().slice(0, 8)}`, clock.nowMs()),
    );
    const session = await storage.createSession(user.id, user);
    assert(await storage.deleteUser(user.id), 'ordinary user was not deleted');
    assert((await storage.getSession(session.id)) === null, 'user session survived deletion');
  }));

  cases.push(runCase('ordinary creation cannot bypass an active claim', createHarness, async (storage, tenantId, clock) => {
    const { claim } = createMaterial(tenantId, clock.nowMs());
    await claimBootstrap(storage, claim);
    const timestamp = new Date(clock.nowMs()).toISOString();
    assert(
      await rejects(() => storage.createUser({
        handle: 'bypass_admin',
        passwordHash: SYNTHETIC_BCRYPT_HASH,
        totpEnabled: false,
        role: 'super_admin',
        isActive: true,
        needsOnboarding: false,
        onboardingStep: 0,
        createdAt: timestamp,
        updatedAt: timestamp,
      })),
      'ordinary user creation bypassed the active claim',
    );
  }));

  cases.push(runCase('bootstrap claim revokes pre-bootstrap privileged sessions', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    const unrelatedUserId = randomUUID();
    const existingSession = await storage.createSession(unrelatedUserId, {
      id: unrelatedUserId,
      handle: 'unrelated_session_actor',
      role: 'super_admin',
    });
    await claimBootstrap(storage, claim);
    assert(
      (await storage.getSession(existingSession.id)) === null,
      'pre-bootstrap privileged session survived bootstrap claim',
    );
    assert(
      await rejects(() => storage.createSession(unrelatedUserId, {
        id: unrelatedUserId,
        role: 'super_admin',
      })),
      'privileged session was created while bootstrap was claimed',
    );

    await finalizeBootstrap(storage, claim, finalization);
    const postBootstrap = await storage.createSession(claim.actor.id, finalization.user);
    assert(
      (await storage.getSession(postBootstrap.id)) !== null,
      'normal post-bootstrap session was weakened',
    );
  }));

  cases.push(runCase('session identity cannot be rebound after bootstrap', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    await claimBootstrap(storage, claim);
    await finalizeBootstrap(storage, claim, finalization);
    const unrelated = await storage.createUser(
      createOrdinaryUser(`session_${randomUUID().slice(0, 8)}`, clock.nowMs()),
    );
    const existingSession = await storage.createSession(unrelated.id, unrelated);
    assert(
      await rejects(() => storage.createSession('unrelated-user', {
        id: claim.actor.id,
        role: 'super_admin',
      })),
      'mismatched nested session identity bypassed claim confinement',
    );
    assert(
      await rejects(() => storage.updateSession(existingSession.id, {
        userId: claim.actor.id,
      })),
      'session userId was rebound to the claimed actor',
    );
    assert(
      await rejects(() => storage.updateSession(existingSession.id, {
        user: {
          ...(existingSession.user ?? {
            id: unrelated.id,
            username: 'unrelated_session_actor',
            name: 'unrelated_session_actor',
            role: 'member',
          }),
          id: claim.actor.id,
        },
      })),
      'nested session identity was rebound to the claimed actor',
    );
    const returned = await storage.getSession(existingSession.id);
    assert(returned !== null, 'post-bootstrap session disappeared');
    returned.userId = claim.actor.id;
    if (returned.user) returned.user.id = claim.actor.id;
    const persisted = await storage.getSession(existingSession.id);
    assert(
      persisted?.userId === unrelated.id &&
        persisted.user?.id === unrelated.id,
      'returned session alias mutated stored identity',
    );
  }));

  cases.push(runCase('returned bootstrap authority is not a mutable alias', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    await claimBootstrap(storage, claim);
    await finalizeBootstrap(storage, claim, finalization);

    const user = await storage.getUser(claim.actor.id);
    const totp = await storage.getTOTPSecret(claim.actor.handle);
    const backupCodes = await storage.getBackupCodes(claim.actor.id);
    assert(user !== null && totp !== null && backupCodes !== null, 'finalized material missing');
    user.role = 'viewer';
    totp.encryptedSecret = 'mutated-outside-adapter';
    backupCodes.codes[0].used = true;

    assert((await storage.getUser(claim.actor.id))?.role === 'super_admin', 'user alias mutated authority');
    assert(
      (await storage.getTOTPSecret(claim.actor.handle))?.encryptedSecret ===
        finalization.totpSecret.encryptedSecret,
      'TOTP alias mutated authority',
    );
    assert(
      (await storage.getBackupCodes(claim.actor.id))?.codes[0].used === false,
      'backup-code alias mutated authority',
    );
  }));

  cases.push(runCase('finalized factors persist and session authority is revocable', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    await claimBootstrap(storage, claim);
    await finalizeBootstrap(storage, claim, finalization);
    assert(
      firstUserBootstrapValueDigest(await storage.getTOTPSecret(claim.actor.handle)) ===
        firstUserBootstrapValueDigest(finalization.totpSecret),
      'finalized TOTP factor did not persist exactly',
    );
    assert(
      firstUserBootstrapValueDigest(await storage.getBackupCodes(claim.actor.id)) ===
        firstUserBootstrapValueDigest(finalization.backupCodes),
      'finalized backup codes did not persist exactly',
    );
    const session = await storage.createSession(claim.actor.id, finalization.user);
    assert(
      (await storage.getSession(session.id))?.userId === claim.actor.id,
      'finalized actor did not receive session authority',
    );
    assert(await storage.deleteSession(session.id), 'finalized actor session was not revoked');
    assert((await storage.getSession(session.id)) === null, 'revoked session remained authoritative');
  }));

  cases.push(runCase('finalized bootstrap factors cannot be deleted independently', createHarness, async (storage, tenantId, clock) => {
    const { claim, finalization } = createMaterial(tenantId, clock.nowMs());
    await claimBootstrap(storage, claim);
    await finalizeBootstrap(storage, claim, finalization);
    assert(
      await rejects(() => storage.deleteTOTPSecret(claim.actor.handle)),
      'finalized TOTP factor was deleted independently',
    );
    assert(
      await rejects(() => storage.deleteBackupCodes(claim.actor.id)),
      'finalized backup codes were deleted independently',
    );
  }));

  const results: FirstUserBootstrapConformanceResult[] = [];
  for (const run of cases) results.push(await run());
  return results;
}
