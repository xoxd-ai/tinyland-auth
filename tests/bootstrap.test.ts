



import { describe, it, expect, beforeEach } from 'vitest';
import { BootstrapService, createBootstrapService } from '../src/modules/bootstrap/index.js';
import { MemoryStorageAdapter } from '../src/storage/memory.js';
import type { BootstrapServiceConfig, BootstrapState } from '../src/modules/bootstrap/index.js';
import type { EncryptedTOTPSecret } from '../src/types/auth.js';
import { generateAuthenticatorToken } from '../src/totp/otplib-compat.js';


const mockGenerateQRCode = async () => 'data:image/png;base64,mockqrcode';
// The service generates and verifies the TOTP secret itself (1.0.0, RS6/RP2),
// so tests compute the real current code from the state they were handed.
const codeFor = (state: BootstrapState) => generateAuthenticatorToken(state.totpSecret);
const wrongCodeFor = (state: BootstrapState) => (codeFor(state) === '000000' ? '000001' : '000000');
const mockEncryptTOTPSecret = async (handle: string, secret: string): Promise<EncryptedTOTPSecret> => ({
  userId: 'pending',
  handle,
  encryptedSecret: `encrypted:${secret}`,
  iv: 'mock-iv',
  authTag: 'mock-tag',
  salt: 'mock-salt',
  createdAt: new Date().toISOString(),
  backupCodesGenerated: false,
  version: 1,
});

describe('BootstrapService', () => {
  let storage: MemoryStorageAdapter;
  let config: BootstrapServiceConfig;
  let service: BootstrapService;

  beforeEach(async () => {
    storage = new MemoryStorageAdapter();
    await storage.init();

    config = {
      storage,
      appName: 'Test App',
      bcryptRounds: 4, 
      backupCodesCount: 5,
      generateQRCode: mockGenerateQRCode,
      encryptTOTPSecret: mockEncryptTOTPSecret,
    };

    service = new BootstrapService(config);
  });

  describe('getStatus', () => {
    it('should indicate bootstrap needed when no users exist', async () => {
      const status = await service.getStatus();

      expect(status.needsBootstrap).toBe(true);
      expect(status.hasUsers).toBe(false);
      expect(status.systemConfigured).toBe(false);
    });

    it('should indicate bootstrap not needed when users exist', async () => {
      await storage.createUser({
        handle: 'existing',
        email: 'existing@test.com',
        passwordHash: 'hash',
        role: 'admin',
        isActive: true,
        totpEnabled: false,
        needsOnboarding: false,
        onboardingStep: 0,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      const status = await service.getStatus();

      expect(status.needsBootstrap).toBe(false);
      expect(status.hasUsers).toBe(true);
      expect(status.systemConfigured).toBe(true);
    });
  });

  describe('initiate', () => {
    it('should create bootstrap state with valid request', async () => {
      const result = await service.initiate({
        handle: 'admin',
        password: 'SecurePassword123!',
        displayName: 'Admin User',
        email: 'admin@test.com',
      });

      expect(result.state).toBeDefined();
      expect(result.state.handle).toBe('admin');
      expect(result.state.displayName).toBe('Admin User');
      expect(result.state.email).toBe('admin@test.com');
      expect(result.state.totpSecret).toMatch(/^[A-Z2-7]{32,}$/);
      expect(result.state.backupCodes).toHaveLength(5);
      expect(result.qrCodeUrl).toBe('data:image/png;base64,mockqrcode');
      expect(result.backupCodes).toEqual(result.state.backupCodes);
    });

    it('should hash the password', async () => {
      const result = await service.initiate({
        handle: 'admin',
        password: 'TestPassword123!',
        displayName: 'Admin',
      });

      expect(result.state.passwordHash).toBeDefined();
      expect(result.state.passwordHash).toMatch(/^\$2[aby]?\$/);
      expect(result.state.passwordHash).not.toBe('TestPassword123!');
    });

    it('should reject invalid handle format', async () => {
      await expect(
        service.initiate({
          handle: '123invalid', 
          password: 'test',
          displayName: 'Test',
        })
      ).rejects.toThrow('Handle must start with a letter');

      await expect(
        service.initiate({
          handle: 'ab', 
          password: 'test',
          displayName: 'Test',
        })
      ).rejects.toThrow('Handle must start with a letter');
    });

    it('should reject if users already exist', async () => {
      await storage.createUser({
        handle: 'existing',
        email: 'existing@test.com',
        passwordHash: 'hash',
        role: 'admin',
        isActive: true,
        totpEnabled: false,
        needsOnboarding: false,
        onboardingStep: 0,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      await expect(
        service.initiate({
          handle: 'newadmin',
          password: 'test',
          displayName: 'Test',
        })
      ).rejects.toThrow('Bootstrap not allowed');
    });
  });

  describe('updateProfile', () => {
    it('should add profile data to state', async () => {
      const { state } = await service.initiate({
        handle: 'admin',
        password: 'test',
        displayName: 'Admin',
      });

      const updated = service.updateProfile(state, {
        bio: 'System administrator',
        pronouns: 'they/them',
      });

      expect(updated.profile).toBeDefined();
      expect(updated.profile?.bio).toBe('System administrator');
      expect(updated.profile?.pronouns).toBe('they/them');
      expect(updated.step).toBe(2);
    });
  });

  describe('complete', () => {
    let validState: BootstrapState;

    beforeEach(async () => {
      const result = await service.initiate({
        handle: 'admin',
        password: 'SecurePassword123!',
        displayName: 'Admin User',
        email: 'admin@test.com',
      });
      validState = result.state;
    });

    it('should complete bootstrap with valid TOTP', async () => {
      const result = await service.complete(validState, {
        handle: 'admin',
        totpCode: codeFor(validState),
      });

      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.user?.handle).toBe('admin');
      expect(result.user?.role).toBe('super_admin');
      expect(result.backupCodes).toHaveLength(5);

      
      const user = await storage.getUserByHandle('admin');
      expect(user).not.toBeNull();
      expect(user?.role).toBe('super_admin');
      expect(user?.totpEnabled).toBe(true);
    });

    it('should reject invalid TOTP code', async () => {
      const result = await service.complete(validState, {
        handle: 'admin',
        totpCode: wrongCodeFor(validState),
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid TOTP code');

      
      const user = await storage.getUserByHandle('admin');
      expect(user).toBeNull();
    });

    it('should reject mismatched handle', async () => {
      const result = await service.complete(validState, {
        handle: 'different',
        totpCode: codeFor(validState),
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Handle mismatch');
    });

    it('should reject expired state', async () => {
      const expiredState: BootstrapState = {
        ...validState,
        timestamp: Date.now() - 15 * 60 * 1000, 
      };

      const result = await service.complete(expiredState, {
        handle: 'admin',
        totpCode: codeFor(validState),
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('expired');
    });

    it('should save TOTP secret and backup codes', async () => {
      await service.complete(validState, {
        handle: 'admin',
        totpCode: codeFor(validState),
      });

      const secret = await storage.getTOTPSecret('admin');
      expect(secret).not.toBeNull();
      expect(secret?.handle).toBe('admin');

      const user = await storage.getUserByHandle('admin');
      const backupCodes = await storage.getBackupCodes(user!.id);
      expect(backupCodes).not.toBeNull();
      expect(backupCodes?.codes).toHaveLength(5);
    });

    it('should log audit event', async () => {
      await service.complete(validState, {
        handle: 'admin',
        totpCode: codeFor(validState),
      });

      const events = await storage.getRecentAuditEvents(10);
      const bootstrapEvent = events.find(e => e.type === 'BOOTSTRAP_COMPLETED');
      expect(bootstrapEvent).toBeDefined();
      expect(bootstrapEvent?.handle).toBe('admin');
    });
  });

  describe('first-admin TOTP is verified by the service (RS6/RP2)', () => {
    let validState: BootstrapState;

    beforeEach(async () => {
      validState = (
        await service.initiate({ handle: 'admin', password: 'SecurePassword123!', displayName: 'Admin User' })
      ).state;
    });

    it('generates a fresh 160-bit secret per initiate', async () => {
      const other = new BootstrapService(config);
      const second = (
        await other.initiate({ handle: 'admin', password: 'SecurePassword123!', displayName: 'Admin User' })
      ).state;
      expect(validState.totpSecret).toMatch(/^[A-Z2-7]{32,}$/);
      expect(second.totpSecret).not.toBe(validState.totpSecret);
    });

    it('ignores a stale verifyTOTP or generateTOTPSecret passed through the config', async () => {
      const pinned = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
      const legacy = new BootstrapService({
        ...config,
        ...({ verifyTOTP: () => true, generateTOTPSecret: () => pinned } as object),
      });
      const { state } = await legacy.initiate({
        handle: 'admin',
        password: 'SecurePassword123!',
        displayName: 'Admin User',
      });
      expect(state.totpSecret).not.toBe(pinned);

      const result = await legacy.complete(state, { handle: 'admin', totpCode: wrongCodeFor(state) });
      expect(result).toEqual({
        success: false,
        error: 'Invalid TOTP code. Please check your authenticator app.',
      });
      expect(await storage.hasUsers()).toBe(false);
    });

    it.each([
      ['empty', ''],
      ['non-numeric', 'accept'],
      ['too long', '1234567890'],
      ['not a string', 123456 as unknown as string],
    ])('rejects a %s code', async (_label, totpCode) => {
      const result = await service.complete(validState, { handle: 'admin', totpCode });
      expect(result.success).toBe(false);
      expect(await storage.hasUsers()).toBe(false);
    });

    it('rejects a state carrying a malformed or below-floor secret instead of throwing', async () => {
      for (const totpSecret of ['MOCK_SECRET_BASE32', 'JBSWY3DP']) {
        const result = await service.complete(
          { ...validState, totpSecret },
          { handle: 'admin', totpCode: '000000' },
        );
        expect(result.success).toBe(false);
      }
      expect(await storage.hasUsers()).toBe(false);
    });

    it('refuses to complete once any user exists (a replayed state or a later second state)', async () => {
      const second = (
        await new BootstrapService(config).initiate({
          handle: 'admin2',
          password: 'SecurePassword123!',
          displayName: 'Second',
        })
      ).state;

      expect((await service.complete(validState, { handle: 'admin', totpCode: codeFor(validState) })).success).toBe(
        true,
      );
      expect(await service.complete(validState, { handle: 'admin', totpCode: codeFor(validState) })).toEqual({
        success: false,
        error: 'Bootstrap not allowed: users already exist',
      });
      expect(await service.complete(second, { handle: 'admin2', totpCode: codeFor(second) })).toEqual({
        success: false,
        error: 'Bootstrap not allowed: users already exist',
      });
      expect(await storage.getUserByHandle('admin2')).toBeNull();
    });
  });

  describe('isStateValid', () => {
    it('should return true for fresh state', async () => {
      const { state } = await service.initiate({
        handle: 'admin',
        password: 'test',
        displayName: 'Admin',
      });

      expect(service.isStateValid(state)).toBe(true);
    });

    it('should return false for expired state', async () => {
      const { state } = await service.initiate({
        handle: 'admin',
        password: 'test',
        displayName: 'Admin',
      });

      const expiredState: BootstrapState = {
        ...state,
        timestamp: Date.now() - 15 * 60 * 1000, 
      };

      expect(service.isStateValid(expiredState, 600000)).toBe(false); 
    });

    it('should return false for invalid state', () => {
      expect(service.isStateValid(null as any)).toBe(false);
      expect(service.isStateValid({} as any)).toBe(false);
    });
  });

  describe('createBootstrapService', () => {
    it('should create service instance', () => {
      const svc = createBootstrapService(config);
      expect(svc).toBeInstanceOf(BootstrapService);
    });
  });
});
