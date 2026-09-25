import { randomBytes, randomUUID, timingSafeEqual } from 'crypto';
import type { BootstrapStorage } from '../../storage/interface.js';
import {
  FirstUserBootstrapConflictError,
  FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS,
  normalizeFirstUserBootstrapTenantId,
  type FirstUserBootstrapFinalization,
  type FirstUserBootstrapReceipt,
  type InertFirstUserClaim,
} from '../../storage/firstUserBootstrap.js';
import {
  AuditEventType,
  type AdminUser,
  type EncryptedTOTPSecret,
} from '../../types/auth.js';
import type {
  BootstrapRequest,
  BootstrapResponse,
  BootstrapVerificationRequest,
  BootstrapStatus,
} from '../../types/api.js';
import { hashPassword } from '../../core/security/password.js';
import {
  createBackupCodeSet,
  generateBackupCodes,
} from '../../core/backup-codes/index.js';
import {
  bootstrapPendingAttemptDigest,
  type BootstrapAttemptStore,
  type BootstrapPendingAttempt,
  type BootstrapProfile,
} from './attempt-store.js';

export interface BootstrapServiceConfig {
  storage: BootstrapStorage;
  attemptStore: BootstrapAttemptStore;
  tenantId: string;
  appName: string;
  bcryptRounds?: number;
  backupCodesCount?: number;
  maxAgeMs?: number;
  generateTOTPSecret: () => string;
  generateQRCode: (handle: string, secret: string, issuer: string) => Promise<string>;
  verifyTOTP: (secret: string, token: string) => boolean | Promise<boolean>;
  encryptTOTPSecret: (handle: string, secret: string) => Promise<EncryptedTOTPSecret>;
  decryptTOTPSecret: (secret: EncryptedTOTPSecret) => Promise<string>;
  /** Override only with a generator that preserves at least 128 bits of entropy. */
  generateAttemptId?: () => string;
  generateId?: () => string;
  now?: () => Date;
}

/** Browser-safe bootstrap state. Credential material remains in attemptStore. */
export interface BootstrapState {
  version: 1;
  attemptId: string;
}

interface ResolvedBootstrapServiceConfig extends BootstrapServiceConfig {
  bcryptRounds: number;
  backupCodesCount: number;
  maxAgeMs: number;
  generateAttemptId: () => string;
  generateId: () => string;
  now: () => Date;
}

function isBoundedId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 256 &&
    !value.includes('\0')
  );
}

function isBootstrapState(value: unknown): value is BootstrapState {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const state = value as Partial<BootstrapState>;
  return state.version === 1 && isStrongAttemptId(state.attemptId);
}

function isStrongAttemptId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length >= 20 &&
    value.length <= 256 &&
    /^[A-Za-z0-9._~-]+$/.test(value)
  );
}

function isSafeActorId(value: unknown): value is string {
  return (
    isBoundedId(value) &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)
  );
}

function normalizeBootstrapInputString(
  value: unknown,
  label: string,
  maximumLength: number,
): string {
  if (typeof value !== 'string' || value.includes('\0')) {
    throw new Error(`${label} must be a string`);
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maximumLength) {
    throw new Error(`${label} has an invalid length`);
  }
  return normalized;
}

function withoutPasswordHash(user: AdminUser): Omit<AdminUser, 'passwordHash'> {
  const { passwordHash: _passwordHash, ...safeUser } = user;
  return safeUser;
}

function secretsMatch(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, 'utf8');
  const rightBytes = Buffer.from(right, 'utf8');
  return (
    leftBytes.length === rightBytes.length &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

export class BootstrapService {
  private readonly config: ResolvedBootstrapServiceConfig;

  constructor(config: BootstrapServiceConfig) {
    const tenantId = normalizeFirstUserBootstrapTenantId(config.tenantId);
    const maxAgeMs =
      config.maxAgeMs ?? FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS;
    if (maxAgeMs !== FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS) {
      throw new Error(
        `Bootstrap maxAgeMs must equal the storage claim window (${FIRST_USER_BOOTSTRAP_CLAIM_MAX_AGE_MS})`,
      );
    }
    this.config = {
      ...config,
      tenantId,
      bcryptRounds: config.bcryptRounds ?? 12,
      backupCodesCount: config.backupCodesCount ?? 10,
      maxAgeMs,
      generateAttemptId:
        config.generateAttemptId ?? (() => randomBytes(24).toString('base64url')),
      generateId: config.generateId ?? randomUUID,
      now: config.now ?? (() => new Date()),
    };
  }

  async getStatus(): Promise<BootstrapStatus> {
    const [hasUsers, receipt, activeAttempt] = await Promise.all([
      this.config.storage.hasUsers(),
      this.config.storage.getFirstUserBootstrapReceipt(this.config.tenantId),
      this.config.attemptStore.getActiveForTenant(this.config.tenantId),
    ]);

    let systemConfigured = false;
    if (receipt) {
      const [user, totpSecret, backupCodes] = await Promise.all([
        this.config.storage.getUser(receipt.userId),
        this.config.storage.getTOTPSecret(receipt.handle),
        this.config.storage.getBackupCodes(receipt.userId),
      ]);
      let totpDecryptable = false;
      if (totpSecret) {
        try {
          totpDecryptable = (await this.config.decryptTOTPSecret(totpSecret)).length > 0;
        } catch {
          totpDecryptable = false;
        }
      }
      systemConfigured = Boolean(
        user &&
          user.id === receipt.userId &&
          user.handle === receipt.handle &&
          user.isActive &&
          user.role === 'super_admin' &&
          user.totpEnabled &&
          user.totpSecretId === receipt.handle &&
          totpSecret &&
          totpDecryptable &&
          totpSecret.userId === receipt.userId &&
          totpSecret.handle === receipt.handle &&
          backupCodes &&
          backupCodes.userId === receipt.userId &&
          backupCodes.codes.some((code) => !code.used),
      );
    }

    return {
      needsBootstrap: !hasUsers && receipt === null && activeAttempt === null,
      hasUsers,
      systemConfigured,
    };
  }

  async initiate(request: BootstrapRequest): Promise<{
    state: BootstrapState;
    qrCodeUrl: string;
    backupCodes: string[];
  }> {
    const status = await this.getStatus();
    if (!status.needsBootstrap) {
      throw new Error('Bootstrap not allowed: users already exist or authority is finalized');
    }
    if (!/^[a-zA-Z][a-zA-Z0-9_-]{2,29}$/.test(request.handle)) {
      throw new Error(
        'Handle must start with a letter, be 3-30 characters, and contain only letters, numbers, underscores, or hyphens',
      );
    }
    const displayName = normalizeBootstrapInputString(
      request.displayName,
      'Display name',
      256,
    );
    let email: string | undefined;
    if (request.email !== undefined) {
      email = normalizeBootstrapInputString(request.email, 'Email', 320).toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        throw new Error('Email is invalid');
      }
    }
    const attemptId = this.config.generateAttemptId();
    const actorId = this.config.generateId();
    if (!isStrongAttemptId(attemptId)) {
      throw new Error(
        'Bootstrap attempt ids must be opaque, URL-safe, and at least 20 characters',
      );
    }
    if (!isSafeActorId(actorId)) {
      throw new Error('Bootstrap actor id is invalid');
    }

    const passwordHash = await hashPassword(request.password, {
      rounds: this.config.bcryptRounds,
    });
    const totpSecret = this.config.generateTOTPSecret();
    const qrCodeUrl = await this.config.generateQRCode(
      request.handle,
      totpSecret,
      this.config.appName,
    );
    const backupCodes = generateBackupCodes(this.config.backupCodesCount);
    const createdAt = this.config.now();
    const claimedAt = createdAt.toISOString();

    const claim: InertFirstUserClaim = {
      version: 1,
      tenantId: this.config.tenantId,
      attemptId,
      actor: {
        id: actorId,
        handle: request.handle,
        isActive: false,
        totpEnabled: false,
        sessionAuthority: false,
        backupCodesGenerated: false,
      },
      claimedAt,
    };
    const pending: BootstrapPendingAttempt = {
      version: 1,
      tenantId: this.config.tenantId,
      attemptId,
      actorId,
      handle: request.handle,
      displayName,
      passwordHash,
      totpSecret,
      backupCodes: [...backupCodes],
      backupCodeSet: {
        ...createBackupCodeSet(actorId, backupCodes),
        generatedAt: claimedAt,
      },
      createdAt: claimedAt,
      expiresAt: new Date(createdAt.getTime() + this.config.maxAgeMs).toISOString(),
    };
    if (email !== undefined) pending.email = email;

    await this.config.attemptStore.create(pending);
    try {
      await this.config.storage.claimFirstUserBootstrap(claim);
    } catch (error) {
      await this.config.attemptStore.delete(this.config.tenantId, attemptId).catch(() => false);
      throw error;
    }

    return {
      state: { version: 1, attemptId },
      qrCodeUrl,
      backupCodes: [...backupCodes],
    };
  }

  async updateProfile(
    state: BootstrapState,
    profile: BootstrapProfile,
  ): Promise<BootstrapState> {
    if (!isBootstrapState(state)) {
      throw new Error('Invalid bootstrap state');
    }
    await this.config.attemptStore.updateProfile(
      this.config.tenantId,
      state.attemptId,
      profile,
    );
    return { version: 1, attemptId: state.attemptId };
  }

  private async responseFromReceipt(
    state: BootstrapState,
    receipt: FirstUserBootstrapReceipt,
  ): Promise<BootstrapResponse> {
    if (receipt.attemptId !== state.attemptId) {
      return {
        success: false,
        error: 'Bootstrap was finalized by a different attempt',
      };
    }
    const user = await this.config.storage.getUser(receipt.userId);
    if (!user || user.handle !== receipt.handle) {
      return {
        success: false,
        error: 'Bootstrap receipt exists but finalized user state is unavailable',
      };
    }
    await this.config.attemptStore.delete(
      this.config.tenantId,
      state.attemptId,
    ).catch(() => false);
    return {
      success: true,
      user: withoutPasswordHash(user),
    };
  }

  private async responseFromCompletedAttempt(
    state: BootstrapState,
    handle: string,
  ): Promise<BootstrapResponse | null> {
    const receipt = await this.config.storage.getFirstUserBootstrapReceipt(
      this.config.tenantId,
    );
    if (!receipt) return null;
    if (handle !== receipt.handle) {
      return { success: false, error: 'Handle mismatch' };
    }
    return this.responseFromReceipt(state, receipt);
  }

  private createFinalization(
    pending: BootstrapPendingAttempt,
    encrypted: EncryptedTOTPSecret,
  ): FirstUserBootstrapFinalization {
    const finalizedAt = this.config.now().toISOString();
    const user: AdminUser = {
      id: pending.actorId,
      handle: pending.handle,
      displayName: pending.displayName,
      passwordHash: pending.passwordHash,
      role: 'super_admin',
      isActive: true,
      totpEnabled: true,
      totpSecretId: pending.handle,
      needsOnboarding: false,
      onboardingStep: 0,
      createdAt: pending.createdAt,
      updatedAt: finalizedAt,
    };
    if (pending.email !== undefined) user.email = pending.email;
    if (pending.profile?.bio !== undefined) user.bio = pending.profile.bio;
    if (pending.profile?.pronouns !== undefined) user.pronouns = pending.profile.pronouns;
    if (pending.profile?.avatarUrl !== undefined) user.avatarUrl = pending.profile.avatarUrl;

    return {
      version: 1,
      tenantId: pending.tenantId,
      attemptId: pending.attemptId,
      finalizedAt,
      user,
      totpSecret: {
        userId: pending.actorId,
        handle: pending.handle,
        encryptedSecret: encrypted.encryptedSecret,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        salt: encrypted.salt,
        createdAt: finalizedAt,
        backupCodesGenerated: true,
        version: Math.max(1, encrypted.version),
      },
      backupCodes: structuredClone(pending.backupCodeSet),
    };
  }

  async complete(
    state: BootstrapState,
    verification: BootstrapVerificationRequest,
  ): Promise<BootstrapResponse> {
    if (!isBootstrapState(state)) {
      return { success: false, error: 'Invalid bootstrap state' };
    }

    try {
      const completed = await this.responseFromCompletedAttempt(
        state,
        verification.handle,
      );
      if (completed) return completed;

      let pending = await this.config.attemptStore.get(
        this.config.tenantId,
        state.attemptId,
      );
      if (!pending) {
        const replay = await this.responseFromCompletedAttempt(
          state,
          verification.handle,
        );
        if (replay) return replay;
        return { success: false, error: 'Invalid or expired bootstrap state' };
      }
      if (pending.handle !== verification.handle) {
        return { success: false, error: 'Handle mismatch' };
      }

      if (!pending.finalization) {
        if (this.config.now().getTime() > Date.parse(pending.expiresAt)) {
          return {
            success: false,
            error: 'Bootstrap session expired. Please start over.',
          };
        }
        const totpValid = await this.config.verifyTOTP(
          pending.totpSecret,
          verification.totpCode,
        );
        if (totpValid !== true) {
          return {
            success: false,
            error: 'Invalid TOTP code. Please check your authenticator app.',
          };
        }

        const encrypted = await this.config.encryptTOTPSecret(
          pending.handle,
          pending.totpSecret,
        );
        const decrypted = await this.config.decryptTOTPSecret(encrypted);
        if (!secretsMatch(decrypted, pending.totpSecret)) {
          throw new Error('Encrypted TOTP round-trip validation failed');
        }
        pending = await this.config.attemptStore.prepareFinalization(
          this.config.tenantId,
          state.attemptId,
          bootstrapPendingAttemptDigest(pending),
          this.createFinalization(pending, encrypted),
        );
      }

      if (!pending.finalization) {
        throw new FirstUserBootstrapConflictError(
          'Bootstrap finalization was not retained by the attempt store',
        );
      }
      const receipt = await this.config.storage.finalizeFirstUserBootstrap(
        pending.finalization,
      );
      const user = await this.config.storage.getUser(receipt.userId);
      if (!user) {
        throw new Error('Bootstrap finalized without a readable user record');
      }

      try {
        await this.config.storage.logAuditEvent({
          timestamp: receipt.finalizedAt,
          type: AuditEventType.BOOTSTRAP_COMPLETED,
          userId: receipt.userId,
          handle: receipt.handle,
          details: {
            attemptId: receipt.attemptId,
            materialDigest: receipt.materialDigest,
            role: 'super_admin',
            totpEnabled: true,
            backupCodesGenerated: pending.backupCodes.length,
          },
          severity: 'info',
          source: 'system',
        });
      } catch {
        // The immutable receipt remains the authority if secondary audit IO fails.
      }

      const response: BootstrapResponse = {
        success: true,
        user: withoutPasswordHash(user),
      };
      await this.config.attemptStore.delete(
        this.config.tenantId,
        pending.attemptId,
      ).catch(() => false);
      return response;
    } catch (error) {
      try {
        const replay = await this.responseFromCompletedAttempt(
          state,
          verification.handle,
        );
        if (replay) return replay;
      } catch (receiptError) {
        return {
          success: false,
          error: receiptError instanceof Error
            ? receiptError.message
            : 'Bootstrap failed',
        };
      }
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Bootstrap failed',
      };
    }
  }

  async isStateValid(
    state: BootstrapState,
    maxAgeMs: number = this.config.maxAgeMs,
  ): Promise<boolean> {
    if (!isBootstrapState(state)) return false;
    const receipt = await this.config.storage.getFirstUserBootstrapReceipt(
      this.config.tenantId,
    );
    if (receipt) return receipt.attemptId === state.attemptId;

    const pending = await this.config.attemptStore.get(
      this.config.tenantId,
      state.attemptId,
    );
    if (!pending) return false;
    return this.config.now().getTime() - Date.parse(pending.createdAt) <= maxAgeMs;
  }
}

export function createBootstrapService(
  config: BootstrapServiceConfig,
): BootstrapService {
  return new BootstrapService(config);
}

export {
  bootstrapPendingAttemptDigest,
  BootstrapAttemptStoreConformanceError,
  MemoryBootstrapAttemptStore,
  runBootstrapAttemptStoreConformance,
  type BootstrapAttemptStore,
  type BootstrapAttemptStoreConformanceHarness,
  type BootstrapAttemptStoreConformanceHarnessFactory,
  type BootstrapAttemptStoreConformanceResult,
  type BootstrapPendingAttempt,
  type BootstrapProfile,
} from './attempt-store.js';
export type {
  BootstrapRequest,
  BootstrapResponse,
  BootstrapVerificationRequest,
  BootstrapStatus,
};
