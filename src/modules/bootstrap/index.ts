









import type { BootstrapStorage } from '../../storage/interface.js';
import type { AdminUser, EncryptedTOTPSecret } from '../../types/auth.js';
import type {
  BootstrapRequest,
  BootstrapResponse,
  BootstrapVerificationRequest,
  BootstrapStatus,
} from '../../types/api.js';
import { hashPassword } from '../../core/security/password.js';
import { generateBackupCodes, createBackupCodeSet } from '../../core/backup-codes/index.js';
import { epochSecondsFor, nowMsFor, seamsOf } from '../../core/seams/index.js';
import {
  generateAuthenticatorSecret,
  verifyAuthenticatorToken,
} from '../../totp/otplib-compat.js';




/**
 * First-admin bootstrap configuration.
 *
 * There is deliberately no TOTP verifier and no TOTP secret generator here
 * (1.0.0, RS6/RP2): the service generates the enrolment secret from the
 * CSPRNG and verifies the authenticator code itself, so no caller-supplied
 * callback can accept an arbitrary code or pin the first admin's seed.
 */
export interface BootstrapServiceConfig {
  
  storage: BootstrapStorage;
  
  appName: string;
  
  bcryptRounds: number;
  
  backupCodesCount: number;
  
  /** Renders the enrolment QR code. Presentation only; it decides nothing. */
  generateQRCode: (handle: string, secret: string, issuer: string) => Promise<string>;
  
  encryptTOTPSecret: (handle: string, secret: string) => Promise<EncryptedTOTPSecret>;
}




/**
 * State carried between `initiate()` and `complete()`.
 *
 * It holds the password hash and the plaintext TOTP secret, and `complete()`
 * trusts it. Keep it server-side (a server session store) or seal it
 * (authenticated encryption) between the two steps; never round-trip it
 * through the client in the clear.
 */
export interface BootstrapState {
  handle: string;
  passwordHash: string;
  displayName: string;
  email?: string;
  totpSecret: string;
  backupCodes: string[];
  timestamp: number;
  step: number;
  profile?: {
    bio?: string;
    pronouns?: string;
    avatarUrl?: string;
  };
}


































export class BootstrapService {
  private config: BootstrapServiceConfig;

  constructor(config: BootstrapServiceConfig) {
    this.config = {
      ...config,
      bcryptRounds: config.bcryptRounds ?? 12,
      backupCodesCount: config.backupCodesCount ?? 10,
    };
  }

  


  /**
   * System time. First-admin bootstrap stays attended (RP2): the clock and the
   * recovery-code generator have no public override; a test build attaches
   * them only through the gated ./testing entry.
   */
  private nowMs(): number {
    return nowMsFor(this);
  }

  async getStatus(): Promise<BootstrapStatus> {
    const hasUsers = await this.config.storage.hasUsers();

    return {
      needsBootstrap: !hasUsers,
      hasUsers,
      systemConfigured: hasUsers,
    };
  }

  





  async initiate(request: BootstrapRequest): Promise<{
    state: BootstrapState;
    qrCodeUrl: string;
    backupCodes: string[];
  }> {
    
    const status = await this.getStatus();
    if (!status.needsBootstrap) {
      throw new Error('Bootstrap not allowed: users already exist');
    }

    
    if (!/^[a-zA-Z][a-zA-Z0-9_-]{2,29}$/.test(request.handle)) {
      throw new Error(
        'Handle must start with a letter, be 3-30 characters, and contain only letters, numbers, underscores, or hyphens'
      );
    }

    
    const passwordHash = await hashPassword(request.password, {
      rounds: this.config.bcryptRounds,
    });

    
    const totpSecret = generateAuthenticatorSecret();

    
    const qrCodeUrl = await this.config.generateQRCode(
      request.handle,
      totpSecret,
      this.config.appName
    );

    
    const backupCodes = (seamsOf(this)?.generateBackupCodes ?? generateBackupCodes)(
      this.config.backupCodesCount
    );

    
    const state: BootstrapState = {
      handle: request.handle,
      passwordHash,
      displayName: request.displayName,
      email: request.email,
      totpSecret,
      backupCodes,
      timestamp: this.nowMs(),
      step: 1,
    };

    return {
      state,
      qrCodeUrl,
      backupCodes,
    };
  }

  


  updateProfile(
    state: BootstrapState,
    profile: { bio?: string; pronouns?: string; avatarUrl?: string }
  ): BootstrapState {
    return {
      ...state,
      profile,
      step: 2,
    };
  }

  


  async complete(
    state: BootstrapState,
    verification: BootstrapVerificationRequest
  ): Promise<BootstrapResponse> {
    
    if (!state || !state.handle || !state.totpSecret) {
      return {
        success: false,
        error: 'Invalid bootstrap state',
      };
    }

    
    const maxAge = 10 * 60 * 1000;
    if (this.nowMs() - state.timestamp > maxAge) {
      return {
        success: false,
        error: 'Bootstrap session expired. Please start over.',
      };
    }

    
    if (state.handle !== verification.handle) {
      return {
        success: false,
        error: 'Handle mismatch',
      };
    }

    
    // First admin is still a fresh install: refuse a replayed state, or a
    // second state, once any user exists. Not atomic: two completes racing
    // before either writes can both pass, so storage should still enforce a
    // unique handle and a single bootstrap.
    if (await this.config.storage.hasUsers()) {
      return {
        success: false,
        error: 'Bootstrap not allowed: users already exist',
      };
    }

    // Verified here, never by a caller-supplied callback (RS6/RP2).
    if (!(await this.verifyCode(state.totpSecret, verification.totpCode))) {
      return {
        success: false,
        error: 'Invalid TOTP code. Please check your authenticator app.',
      };
    }

    try {
      
      const encryptedSecret = await this.config.encryptTOTPSecret(
        state.handle,
        state.totpSecret
      );
      await this.config.storage.saveTOTPSecret(state.handle, encryptedSecret);

      
      const savedSecret = await this.config.storage.getTOTPSecret(state.handle);
      if (!savedSecret) {
        throw new Error('Failed to verify TOTP secret was saved');
      }

      
      const backupCodeSet = createBackupCodeSet(
        'pending', 
        state.backupCodes
      );

      
      const user = await this.config.storage.createUser({
        handle: state.handle,
        email: state.email,
        displayName: state.displayName,
        passwordHash: state.passwordHash,
        role: 'super_admin',
        isActive: true,
        totpEnabled: true,
        totpSecretId: state.handle,
        needsOnboarding: false,
        onboardingStep: 0,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        bio: state.profile?.bio,
        pronouns: state.profile?.pronouns,
        avatarUrl: state.profile?.avatarUrl,
      });

      
      backupCodeSet.userId = user.id;
      await this.config.storage.saveBackupCodes(user.id, backupCodeSet);

      
      await this.config.storage.logAuditEvent({
        timestamp: new Date().toISOString(),
        type: 'BOOTSTRAP_COMPLETED' as any,
        userId: user.id,
        handle: user.handle,
        details: {
          role: 'super_admin',
          totpEnabled: true,
          backupCodesGenerated: state.backupCodes.length,
        },
        severity: 'info',
        source: 'system',
      });

      
      const safeUser: Omit<AdminUser, 'passwordHash'> = {
        ...user,
      };
      delete (safeUser as any).passwordHash;

      return {
        success: true,
        user: safeUser as any,
        backupCodes: state.backupCodes,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Bootstrap failed',
      };
    }
  }

  


  private async verifyCode(secret: string, code: unknown): Promise<boolean> {
    if (typeof code !== 'string' || !/^\d{6,8}$/.test(code)) {
      return false;
    }
    try {
      return await verifyAuthenticatorToken(secret, code, epochSecondsFor(this));
    } catch {
      // A state carrying a malformed or below-floor secret never verifies.
      return false;
    }
  }

  isStateValid(state: BootstrapState, maxAgeMs: number = 600000): boolean {
    if (!state || !state.timestamp) {
      return false;
    }
    return this.nowMs() - state.timestamp < maxAgeMs;
  }
}




export function createBootstrapService(
  config: BootstrapServiceConfig
): BootstrapService {
  return new BootstrapService(config);
}


export type { BootstrapRequest, BootstrapResponse, BootstrapVerificationRequest, BootstrapStatus };
