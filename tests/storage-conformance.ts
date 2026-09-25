import { createHash } from 'crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { IStorageAdapter } from '../src/storage/interface.js';
import {
  FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS,
  FirstUserBootstrapConflictError,
  firstUserBootstrapMaterialDigest,
  firstUserBootstrapValueDigest,
  isValidInertFirstUserClaim,
  type FirstUserBootstrapFinalization,
  type InertFirstUserClaim,
} from '../src/storage/firstUserBootstrap.js';

const TENANT = '12345678-1234-4123-8123-123456789abc';
const SYNTHETIC_BCRYPT_HASH = `$2b$04$${'A'.repeat(53)}`;

export interface StorageConformanceHarness {
  storage: IStorageAdapter;
  cleanup(): Promise<void>;
}

export type StorageConformanceFactory = (
  tenantId: string,
) => Promise<StorageConformanceHarness>;

function syntheticHash(label: string): string {
  return createHash('sha256').update(`synthetic-${label}`).digest('hex');
}

export function makeClaim(
  overrides: Partial<InertFirstUserClaim> = {},
): InertFirstUserClaim {
  return {
    version: 1,
    tenantId: TENANT,
    attemptId: 'synthetic-attempt-1',
    actor: {
      id: 'synthetic-user-1',
      handle: 'bootstrap_admin',
      isActive: false,
      totpEnabled: false,
      sessionAuthority: false,
      backupCodesGenerated: false,
    },
    claimedAt: new Date(Date.now() - 1000).toISOString(),
    ...overrides,
  };
}

export function makeFinalization(
  claim: InertFirstUserClaim,
): FirstUserBootstrapFinalization {
  const finalizedAt = new Date().toISOString();
  return {
    version: 1,
    tenantId: claim.tenantId,
    attemptId: claim.attemptId,
    finalizedAt,
    user: {
      id: claim.actor.id,
      handle: claim.actor.handle,
      displayName: 'Synthetic Bootstrap Admin',
      passwordHash: SYNTHETIC_BCRYPT_HASH,
      totpEnabled: true,
      totpSecretId: claim.actor.handle,
      role: 'super_admin',
      isActive: true,
      needsOnboarding: false,
      onboardingStep: 0,
      createdAt: claim.claimedAt,
      updatedAt: finalizedAt,
    },
    totpSecret: {
      userId: claim.actor.id,
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
      userId: claim.actor.id,
      generatedAt: finalizedAt,
      codes: [
        {
          id: 'synthetic-backup-1',
          hash: syntheticHash('backup-1'),
          used: false,
        },
        {
          id: 'synthetic-backup-2',
          hash: syntheticHash('backup-2'),
          used: false,
        },
      ],
    },
  };
}

function makeOrdinaryUser(
  handle: string,
): Omit<FirstUserBootstrapFinalization['user'], 'id'> {
  const timestamp = new Date().toISOString();
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

export function describeStorageConformance(
  name: string,
  createHarness: StorageConformanceFactory,
): void {
  describe(`${name} atomic first-user bootstrap storage conformance`, () => {
    let harness: StorageConformanceHarness;
    let storage: IStorageAdapter;

    beforeEach(async () => {
      harness = await createHarness(TENANT);
      storage = harness.storage;
      await storage.init();
    });

    afterEach(async () => {
      await storage.close();
      await harness.cleanup();
    });

    it('allows exactly one of two concurrent claims to win', async () => {
      const first = makeClaim();
      const second = makeClaim({
        attemptId: 'synthetic-attempt-2',
        actor: { ...makeClaim().actor, id: 'synthetic-user-2' },
      });

      const results = await Promise.allSettled([
        storage.claimFirstUserBootstrap(first),
        storage.claimFirstUserBootstrap(second),
      ]);

      expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      const rejected = results.find((result) => result.status === 'rejected');
      expect(rejected?.status).toBe('rejected');
      if (rejected?.status === 'rejected') {
        expect(rejected.reason).toBeInstanceOf(FirstUserBootstrapConflictError);
      }
    });

    it('rejects ordinary creation before first-user finalization', async () => {
      await expect(
        storage.createUser(makeOrdinaryUser('ordinary_first_user')),
      ).rejects.toThrow(/finalized first-user bootstrap receipt/i);
      expect(await storage.hasUsers()).toBe(false);
      expect(await storage.getFirstUserBootstrapReceipt(TENANT)).toBeNull();
    });

    it('rejects active or credentialed claims through the reusable validator', async () => {
      const active = makeClaim();
      (active.actor as { isActive: boolean }).isActive = true;
      expect(isValidInertFirstUserClaim(active)).toBe(false);
      await expect(storage.claimFirstUserBootstrap(active)).rejects.toThrow();

      const credentialed = makeClaim();
      (credentialed.actor as unknown as { passwordHash: string }).passwordHash =
        SYNTHETIC_BCRYPT_HASH;
      expect(isValidInertFirstUserClaim(credentialed)).toBe(false);
      await expect(storage.claimFirstUserBootstrap(credentialed)).rejects.toThrow();
    });

    it('rejects unknown, missing, and non-JSON claim fields before mutation', async () => {
      const malformed: InertFirstUserClaim[] = [];
      const unknown = makeClaim() as InertFirstUserClaim & { credential?: string };
      unknown.credential = 'alias';
      malformed.push(unknown);
      const missing = makeClaim() as InertFirstUserClaim & { claimedAt?: string };
      delete missing.claimedAt;
      malformed.push(missing as InertFirstUserClaim);
      const undefinedField = makeClaim() as InertFirstUserClaim & { note?: undefined };
      undefinedField.note = undefined;
      malformed.push(undefinedField);

      for (const claim of malformed) {
        await expect(storage.claimFirstUserBootstrap(claim)).rejects.toThrow();
      }
      await expect(storage.claimFirstUserBootstrap(makeClaim())).resolves.toMatchObject({
        tenantId: TENANT,
      });
      expect(await storage.hasUsers()).toBe(false);
    });

    it('uses an injective canonical JSON digest and rejects lossy values', () => {
      expect(firstUserBootstrapValueDigest({ value: 0 })).not.toBe(
        firstUserBootstrapValueDigest({ value: null }),
      );
      const sparse = new Array(1);
      const accessor = Object.defineProperty({}, 'value', {
        enumerable: true,
        get: () => 'not-data',
      });
      const symbolKey = { value: 'visible' } as Record<PropertyKey, unknown>;
      symbolKey[Symbol('hidden')] = 'not-json';
      const cycle: Record<string, unknown> = {};
      cycle.self = cycle;
      for (const value of [
        undefined,
        Number.NaN,
        Number.POSITIVE_INFINITY,
        Number.NEGATIVE_INFINITY,
        -0,
        () => undefined,
        Symbol('non-json'),
        1n,
        sparse,
        new Date(),
        new Map([['value', 'not-json']]),
        accessor,
        symbolKey,
        cycle,
      ]) {
        expect(() => firstUserBootstrapValueDigest(value)).toThrow();
      }
    });

    it('keeps a successful claim inert until finalization', async () => {
      const claim = makeClaim();
      await storage.claimFirstUserBootstrap(claim);

      expect(await storage.hasUsers()).toBe(false);
      expect(await storage.getUser(claim.actor.id)).toBeNull();
      expect(await storage.getTOTPSecret(claim.actor.handle)).toBeNull();
      expect(await storage.getBackupCodes(claim.actor.id)).toBeNull();
      await expect(
        storage.createSession(claim.actor.id, { id: claim.actor.id }),
      ).rejects.toThrow(/session authority/);
      await expect(
        storage.saveTOTPSecret(claim.actor.handle, makeFinalization(claim).totpSecret),
      ).rejects.toThrow(/before finalization/);
      await expect(
        storage.saveBackupCodes(claim.actor.id, makeFinalization(claim).backupCodes),
      ).rejects.toThrow(/before finalization/);
    });

    it('revokes unrelated privileged sessions when a claim is accepted', async () => {
      const claim = makeClaim();
      const unrelatedUserId = 'pre-bootstrap-privileged-session';
      const session = await storage.createSession(unrelatedUserId, {
        id: unrelatedUserId,
        handle: 'pre_bootstrap_admin',
        role: 'super_admin',
      });

      await expect(storage.claimFirstUserBootstrap(claim)).resolves.toEqual(claim);
      expect(await storage.getSession(session.id)).toBeNull();
      await expect(storage.createSession(unrelatedUserId, {
        id: unrelatedUserId,
        role: 'super_admin',
      })).rejects.toThrow(/session authority|before finalization/i);

      const finalization = makeFinalization(claim);
      await storage.finalizeFirstUserBootstrap(finalization);
      const postBootstrap = await storage.createSession(claim.actor.id, finalization.user);
      expect(await storage.getSession(postBootstrap.id)).not.toBeNull();
    });

    it('replays an exact expired claim and safely replaces an abandoned one', async () => {
      const startedAt = Date.now();
      vi.useFakeTimers();
      try {
        vi.setSystemTime(startedAt);
        const original = makeClaim({
          claimedAt: new Date(startedAt).toISOString(),
        });
        await storage.claimFirstUserBootstrap(original);

        vi.setSystemTime(startedAt + 11 * 60 * 1000);
        await expect(
          storage.claimFirstUserBootstrap(structuredClone(original)),
        ).resolves.toEqual(original);

        const replacement = makeClaim({
          attemptId: 'synthetic-attempt-replacement',
          actor: {
            ...original.actor,
            id: 'synthetic-user-replacement',
            handle: 'replacement_admin',
          },
          claimedAt: new Date(startedAt + 11 * 60 * 1000).toISOString(),
        });
        await expect(storage.claimFirstUserBootstrap(replacement)).resolves.toEqual(
          replacement,
        );
        await expect(
          storage.finalizeFirstUserBootstrap(makeFinalization(original)),
        ).rejects.toThrow(/does not match|active claim|claim lifetime/i);
      } finally {
        vi.useRealTimers();
      }
    });

    it('accepts finalization at the exact 600000 ms claim boundary', async () => {
      const startedAt = Date.now();
      vi.useFakeTimers();
      try {
        expect(FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS).toBe(600_000);
        vi.setSystemTime(startedAt);
        const claim = makeClaim({
          claimedAt: new Date(startedAt).toISOString(),
        });
        await storage.claimFirstUserBootstrap(claim);

        vi.setSystemTime(startedAt + 600_000);
        await expect(
          storage.finalizeFirstUserBootstrap(makeFinalization(claim)),
        ).resolves.toMatchObject({
          tenantId: TENANT,
          attemptId: claim.attemptId,
        });
      } finally {
        vi.useRealTimers();
      }
    });

    it('rejects finalization at 600001 ms without clock-skew grace', async () => {
      const startedAt = Date.now();
      vi.useFakeTimers();
      try {
        vi.setSystemTime(startedAt);
        const claim = makeClaim({
          claimedAt: new Date(startedAt).toISOString(),
        });
        await storage.claimFirstUserBootstrap(claim);

        vi.setSystemTime(startedAt + 600_000);
        const finalization = makeFinalization(claim);
        vi.setSystemTime(startedAt + 600_001);
        await expect(
          storage.finalizeFirstUserBootstrap(finalization),
        ).rejects.toThrow(/outside the active claim window/i);
        expect(await storage.hasUsers()).toBe(false);
      } finally {
        vi.useRealTimers();
      }
    });

    it('rejects a forged year-2000 claim timestamp before finalization', async () => {
      const claim = makeClaim();
      const finalization = makeFinalization(claim);
      finalization.user.createdAt = '2000-01-01T00:00:00.000Z';
      await storage.claimFirstUserBootstrap(claim);

      await expect(
        storage.finalizeFirstUserBootstrap(finalization),
      ).rejects.toThrow(/claim lifetime|claim timestamp/i);
      expect(await storage.hasUsers()).toBe(false);
      expect(await storage.getFirstUserBootstrapReceipt(TENANT)).toBeNull();
    });

    it('rejects missing, mismatched, and already-consumed claims', async () => {
      const claim = makeClaim();
      const finalization = makeFinalization(claim);
      await expect(storage.finalizeFirstUserBootstrap(finalization)).rejects.toThrow(
        /no active first-user bootstrap claim/i,
      );

      await storage.claimFirstUserBootstrap(claim);
      const mismatch = makeFinalization({
        ...claim,
        attemptId: 'different-bootstrap-attempt',
      });
      await expect(storage.finalizeFirstUserBootstrap(mismatch)).rejects.toThrow(
        /does not match|active claim/i,
      );
      expect(await storage.hasUsers()).toBe(false);

      await storage.finalizeFirstUserBootstrap(finalization);
      await expect(storage.claimFirstUserBootstrap(claim)).rejects.toThrow(
        /already finalized/i,
      );
      await expect(storage.claimFirstUserBootstrap(makeClaim({
        attemptId: 'new-bootstrap-attempt',
      }))).rejects.toThrow(/already finalized/i);
    });

    it('returns the immutable receipt for an exact finalization replay', async () => {
      const claim = makeClaim();
      const finalization = makeFinalization(claim);
      await storage.claimFirstUserBootstrap(claim);

      const receipt = await storage.finalizeFirstUserBootstrap(finalization);
      const replay = await storage.finalizeFirstUserBootstrap(finalization);

      expect(replay).toEqual(receipt);
      expect(await storage.getFirstUserBootstrapReceipt(TENANT)).toEqual(receipt);
      expect(await storage.getUser(claim.actor.id)).toEqual(finalization.user);
      expect(await storage.getTOTPSecret(claim.actor.handle)).toEqual(
        finalization.totpSecret,
      );
      expect(await storage.getBackupCodes(claim.actor.id)).toEqual(
        finalization.backupCodes,
      );
    });

    it('returns one receipt for concurrent exact finalization', async () => {
      const claim = makeClaim();
      const finalization = makeFinalization(claim);
      await storage.claimFirstUserBootstrap(claim);

      const receipts = await Promise.all([
        storage.finalizeFirstUserBootstrap(finalization),
        storage.finalizeFirstUserBootstrap(finalization),
      ]);
      expect(receipts[0]).toEqual(receipts[1]);
    });

    it('allows exactly one of two conflicting finalizations to win', async () => {
      const claim = makeClaim();
      const first = makeFinalization(claim);
      const second = structuredClone(first);
      second.user.displayName = 'Competing Bootstrap Admin';
      await storage.claimFirstUserBootstrap(claim);

      const outcomes = await Promise.allSettled([
        storage.finalizeFirstUserBootstrap(first),
        storage.finalizeFirstUserBootstrap(second),
      ]);
      expect(outcomes.filter((outcome) => outcome.status === 'fulfilled')).toHaveLength(1);
      expect(outcomes.filter((outcome) => outcome.status === 'rejected')).toHaveLength(1);
      const winner = outcomes[0].status === 'fulfilled' ? first : second;
      expect(await storage.getFirstUserBootstrapReceipt(TENANT)).toMatchObject({
        materialDigest: firstUserBootstrapMaterialDigest(winner),
      });
      expect(await storage.getUser(claim.actor.id)).toMatchObject({
        displayName: winner.user.displayName,
      });
    });

    it('rejects a mismatched finalization replay', async () => {
      const claim = makeClaim();
      const finalization = makeFinalization(claim);
      await storage.claimFirstUserBootstrap(claim);
      await storage.finalizeFirstUserBootstrap(finalization);

      const mismatch = structuredClone(finalization);
      mismatch.user.displayName = 'Different Synthetic Admin';
      await expect(storage.finalizeFirstUserBootstrap(mismatch)).rejects.toThrow(
        /immutable completion receipt/,
      );
    });

    it('validates a completed replay before digest comparison', async () => {
      const claim = makeClaim();
      const finalization = makeFinalization(claim);
      await storage.claimFirstUserBootstrap(claim);
      const receipt = await storage.finalizeFirstUserBootstrap(finalization);

      const invalidReplay = structuredClone(finalization);
      invalidReplay.user.onboardingStep = -0;
      await expect(storage.finalizeFirstUserBootstrap(invalidReplay)).rejects.toThrow();

      const sparseReplay = structuredClone(finalization);
      sparseReplay.backupCodes.codes = new Array(2);
      await expect(storage.finalizeFirstUserBootstrap(sparseReplay)).rejects.toThrow();

      const undefinedReplay = structuredClone(finalization);
      undefinedReplay.user.email = undefined;
      await expect(storage.finalizeFirstUserBootstrap(undefinedReplay)).rejects.toThrow();
      expect(await storage.getFirstUserBootstrapReceipt(TENANT)).toEqual(receipt);
    });

    it('does not change the receipt when mutable current state changes', async () => {
      const claim = makeClaim();
      const finalization = makeFinalization(claim);
      await storage.claimFirstUserBootstrap(claim);
      const receipt = await storage.finalizeFirstUserBootstrap(finalization);

      await storage.updateUser(claim.actor.id, { displayName: 'Updated Current Name' });
      await storage.saveTOTPSecret(claim.actor.handle, {
        ...finalization.totpSecret,
        version: 2,
      });
      await storage.saveBackupCodes(claim.actor.id, {
        ...finalization.backupCodes,
        lastUsedAt: new Date().toISOString(),
        codes: finalization.backupCodes.codes.map((code, index) =>
          index === 0
            ? { ...code, used: true, usedAt: new Date().toISOString() }
            : code,
        ),
      });

      expect(await storage.getFirstUserBootstrapReceipt(TENANT)).toEqual(receipt);
      expect(await storage.finalizeFirstUserBootstrap(finalization)).toEqual(receipt);
      expect((await storage.getUser(claim.actor.id))?.displayName).toBe(
        'Updated Current Name',
      );
    });

    it('rejects deletion of claimed and finalized actors', async () => {
      const claim = makeClaim();
      const finalization = makeFinalization(claim);
      await storage.claimFirstUserBootstrap(claim);
      await expect(storage.deleteUser(claim.actor.id)).rejects.toThrow(/claimed/);

      await storage.finalizeFirstUserBootstrap(finalization);
      const session = await storage.createSession(claim.actor.id, finalization.user);
      await expect(storage.deleteUser(claim.actor.id)).rejects.toThrow(/finalized/);
      expect(await storage.getSession(session.id)).not.toBeNull();
    });

    it('keeps session identity immutable and returned sessions detached', async () => {
      const claim = makeClaim();
      await storage.claimFirstUserBootstrap(claim);
      await storage.finalizeFirstUserBootstrap(makeFinalization(claim));
      const unrelated = await storage.createUser(
        makeOrdinaryUser('unrelated_session_user'),
      );
      const session = await storage.createSession(unrelated.id, unrelated);

      await expect(storage.updateSession(session.id, {
        userId: claim.actor.id,
      })).rejects.toThrow(/identity is immutable/i);
      await expect(storage.updateSession(session.id, {
        user: { ...session.user!, id: claim.actor.id },
      })).rejects.toThrow(/identity is immutable/i);

      const returned = await storage.getSession(session.id);
      expect(returned).not.toBeNull();
      returned!.userId = claim.actor.id;
      returned!.user!.id = claim.actor.id;
      expect(await storage.getSession(session.id)).toMatchObject({
        userId: unrelated.id,
        user: { id: unrelated.id },
      });
    });

    it('revokes sessions before deleting an ordinary non-finalized user', async () => {
      const claim = makeClaim();
      await storage.claimFirstUserBootstrap(claim);
      await storage.finalizeFirstUserBootstrap(makeFinalization(claim));
      const user = await storage.createUser(makeOrdinaryUser('ordinary_user'));
      const session = await storage.createSession(user.id, user);

      expect(await storage.deleteUser(user.id)).toBe(true);
      expect(await storage.getSession(session.id)).toBeNull();
      expect(await storage.getUser(user.id)).toBeNull();
    });

    it('preserves ordinary creation after first-user finalization', async () => {
      const claim = makeClaim();
      await storage.claimFirstUserBootstrap(claim);
      await storage.finalizeFirstUserBootstrap(makeFinalization(claim));

      const ordinary = await storage.createUser(makeOrdinaryUser('post_bootstrap_user'));
      expect(ordinary.id).not.toBe(claim.actor.id);
      expect(await storage.getAllUsers()).toHaveLength(2);
      expect(await storage.getUser(ordinary.id)).toEqual(ordinary);
    });

    it('does not let ordinary creation steal a finalize race', async () => {
      const claim = makeClaim();
      const finalization = makeFinalization(claim);
      await storage.claimFirstUserBootstrap(claim);
      const ordinaryData = makeOrdinaryUser('racing_ordinary_user');

      const [ordinary, finalized] = await Promise.allSettled([
        storage.createUser(ordinaryData),
        storage.finalizeFirstUserBootstrap(finalization),
      ]);
      expect(finalized.status).toBe('fulfilled');
      expect(await storage.getUser(claim.actor.id)).toEqual(finalization.user);
      expect(await storage.getFirstUserBootstrapReceipt(TENANT)).not.toBeNull();
      if (ordinary.status === 'fulfilled') {
        expect(await storage.getUser(ordinary.value.id)).toEqual(ordinary.value);
      } else {
        expect(await storage.getUserByHandle(ordinaryData.handle)).toBeNull();
      }
    });

    it('rejects invalid bcrypt, factor-use, backup uniqueness, and timestamps', async () => {
      const invalidCases: Array<(value: FirstUserBootstrapFinalization) => void> = [
        (value) => { value.user.passwordHash = '$2b$04$not-a-bcrypt-hash'; },
        (value) => { value.user.role = 'viewer'; },
        (value) => {
          Reflect.deleteProperty(
            value.user as unknown as Record<string, unknown>,
            'needsOnboarding',
          );
        },
        (value) => { value.user.email = undefined; },
        (value) => { value.user.email = 'ADMIN@TEST.COM'; },
        (value) => { value.user.email = 'admin@@test.com'; },
        (value) => { value.user.email = 'admin@.test'; },
        (value) => { value.user.email = 'admin@test.'; },
        (value) => { value.user.email = 'admin\u00a0@test.com'; },
        (value) => { value.user.isLocked = true; },
        (value) => { value.user.loginAttempts = 1; },
        (value) => { value.user.permissions = ['z:last', 'a:first']; },
        (value) => { value.user.onboardingStep = -0; },
        (value) => {
          (value.user as unknown as Record<string, unknown>).displayName =
            () => undefined;
        },
        (value) => {
          Object.assign(value.user as unknown as Record<string, unknown>, {
            browserFingerprint: 'not-bootstrap-authority',
            tempoTraceId: 'not-bootstrap-authority',
          });
        },
        (value) => { value.totpSecret.lastUsedTotpStep = 1; },
        (value) => { value.backupCodes.codes[1].hash = value.backupCodes.codes[0].hash; },
        (value) => {
          value.totpSecret.createdAt = new Date(
            Date.parse(value.finalizedAt) + 1000,
          ).toISOString();
        },
      ];

      for (const mutate of invalidCases) {
        const isolated = await createHarness(TENANT);
        await isolated.storage.init();
        try {
          const claim = makeClaim();
          const finalization = makeFinalization(claim);
          mutate(finalization);
          await isolated.storage.claimFirstUserBootstrap(claim);
          await expect(
            isolated.storage.finalizeFirstUserBootstrap(finalization),
          ).rejects.toThrow();
          expect(await isolated.storage.hasUsers()).toBe(false);
          expect(await isolated.storage.getUser(claim.actor.id)).toBeNull();
          expect(await isolated.storage.getTOTPSecret(claim.actor.handle)).toBeNull();
          expect(await isolated.storage.getBackupCodes(claim.actor.id)).toBeNull();
          expect(
            await isolated.storage.getFirstUserBootstrapReceipt(claim.tenantId),
          ).toBeNull();
        } finally {
          await isolated.storage.close();
          await isolated.cleanup();
        }
      }
    });
  });
}
