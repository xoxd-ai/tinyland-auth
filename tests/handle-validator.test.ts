






import { describe, it, expect, beforeEach } from 'vitest';
import {
  validateHandle,
  addHandle,
  removeHandle,
  listHandles,
  type HandleValidatorConfig,
} from '../src/validation/handle-validator.js';
import { MemoryStorageAdapter } from '../src/storage/index.js';
import { hashPassword } from '../src/core/security/password.js';
import { makeClaim, makeFinalization } from './storage-conformance.js';

function createTestConfig(storage?: MemoryStorageAdapter): HandleValidatorConfig {
  return {
    storage: storage || new MemoryStorageAdapter(),
    logger: () => {},
    timingDelayMs: 0, 
  };
}

async function createTestUser(storage: MemoryStorageAdapter, handle: string, password: string) {
  const passwordHash = await hashPassword(password, { rounds: 4 });
  if (!(await storage.hasUsers())) {
    const baseClaim = makeClaim();
    const claim = makeClaim({
      attemptId: `bootstrap-attempt-${handle}`,
      actor: {
        ...baseClaim.actor,
        id: `bootstrap-user-${handle}`,
        handle,
      },
      claimedAt: new Date().toISOString(),
    });
    const finalization = makeFinalization(claim);
    finalization.user.email = `${handle}@example.com`;
    finalization.user.passwordHash = passwordHash;
    await storage.claimFirstUserBootstrap(claim);
    await storage.finalizeFirstUserBootstrap(finalization);
    return;
  }
  await storage.createUser({
    handle,
    email: `${handle}@example.com`,
    passwordHash,
    role: 'admin',
    isActive: true,
    needsOnboarding: false,
    onboardingStep: 0,
    totpEnabled: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
}

async function bootstrapTestAuthority(storage: MemoryStorageAdapter): Promise<void> {
  await createTestUser(storage, 'bootstrap_admin', 'bootstrap-password');
}

describe('Handle Validator', () => {
  let storage: MemoryStorageAdapter;
  let config: HandleValidatorConfig;

  beforeEach(async () => {
    storage = new MemoryStorageAdapter();
    await storage.init();
    config = createTestConfig(storage);
  });

  describe('validateHandle', () => {
    it('should validate a correct handle and password', async () => {
      await createTestUser(storage, 'testuser', 'correctpassword');

      const result = await validateHandle('testuser', 'correctpassword', config);
      expect(result.isValid).toBe(true);
      expect(result.userId).toBeTruthy();
    });

    it('should reject an incorrect password', async () => {
      await createTestUser(storage, 'testuser', 'correctpassword');

      const result = await validateHandle('testuser', 'wrongpassword', config);
      expect(result.isValid).toBe(false);
      expect(result.userId).toBeUndefined();
    });

    it('should reject a non-existent handle', async () => {
      const result = await validateHandle('nonexistent', 'anypassword', config);
      expect(result.isValid).toBe(false);
    });

    it('should reject an inactive user', async () => {
      await bootstrapTestAuthority(storage);
      const passwordHash = await hashPassword('password', { rounds: 4 });
      await storage.createUser({
        handle: 'inactiveuser',
        email: 'inactive@example.com',
        passwordHash,
        role: 'admin',
        isActive: false,
        needsOnboarding: false,
        onboardingStep: 0,
        totpEnabled: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      const result = await validateHandle('inactiveuser', 'password', config);
      expect(result.isValid).toBe(false);
    });

    it('should handle empty handle gracefully', async () => {
      const result = await validateHandle('', 'password', config);
      expect(result.isValid).toBe(false);
    });

    it('should handle empty password gracefully', async () => {
      await createTestUser(storage, 'testuser', 'password');

      const result = await validateHandle('testuser', '', config);
      expect(result.isValid).toBe(false);
    });
  });

  describe('addHandle', () => {
    beforeEach(async () => {
      await bootstrapTestAuthority(storage);
    });

    it('should add a new handle successfully', async () => {
      const result = await addHandle('newuser', 'SecurePass123!', config);
      expect(result).toBe(true);

      
      const user = await storage.getUserByHandle('newuser');
      expect(user).not.toBeNull();
      expect(user!.handle).toBe('newuser');
    });

    it('should reject duplicate handles', async () => {
      await addHandle('existinguser', 'Password1!', config);

      const result = await addHandle('existinguser', 'AnotherPass1!', config);
      expect(result).toBe(false);
    });

    it('should create user with hashed password', async () => {
      await addHandle('hashtest', 'MyPassword123!', config);

      const user = await storage.getUserByHandle('hashtest');
      expect(user).not.toBeNull();
      
      expect(user!.passwordHash).toMatch(/^\$2[aby]?\$/);
      
      expect(user!.passwordHash).not.toBe('MyPassword123!');
    });

    it('should set new users as active', async () => {
      await addHandle('activeuser', 'Password123!', config);

      const user = await storage.getUserByHandle('activeuser');
      expect(user!.isActive).toBe(true);
    });

    it('should set needsOnboarding for new users', async () => {
      await addHandle('newbie', 'Password123!', config);

      const user = await storage.getUserByHandle('newbie');
      expect(user!.needsOnboarding).toBe(true);
    });
  });

  describe('removeHandle', () => {
    beforeEach(async () => {
      await bootstrapTestAuthority(storage);
    });

    it('should remove an existing handle', async () => {
      await createTestUser(storage, 'removeme', 'password');

      const result = await removeHandle('removeme', config);
      expect(result).toBe(true);

      
      const user = await storage.getUserByHandle('removeme');
      expect(user).toBeNull();
    });

    it('should return false for non-existent handle', async () => {
      const result = await removeHandle('nonexistent', config);
      expect(result).toBe(false);
    });
  });

  describe('listHandles', () => {
    it('should list all active handles', async () => {
      await createTestUser(storage, 'user1', 'pass1');
      await createTestUser(storage, 'user2', 'pass2');
      await createTestUser(storage, 'user3', 'pass3');

      const handles = await listHandles(config);
      expect(handles).not.toBeNull();
      expect(handles!.length).toBe(3);
      expect(handles).toContain('user1');
      expect(handles).toContain('user2');
      expect(handles).toContain('user3');
    });

    it('should return empty array when no users exist', async () => {
      const handles = await listHandles(config);
      expect(handles).not.toBeNull();
      expect(handles!.length).toBe(0);
    });

    it('should exclude inactive users', async () => {
      await createTestUser(storage, 'activeuser', 'pass');
      const passwordHash = await hashPassword('pass', { rounds: 4 });
      await storage.createUser({
        handle: 'inactiveuser',
        email: 'inactive@test.com',
        passwordHash,
        role: 'viewer',
        isActive: false,
        needsOnboarding: false,
        onboardingStep: 0,
        totpEnabled: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      const handles = await listHandles(config);
      expect(handles).toContain('activeuser');
      expect(handles).not.toContain('inactiveuser');
    });
  });
});
