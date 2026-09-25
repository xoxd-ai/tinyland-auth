






import { describe, it, expect, beforeEach } from 'vitest';
import { SessionManager, createSessionManager, classifyDevice, extractBrowserInfo } from '../src/core/session/index.js';
import { MemoryStorageAdapter } from '../src/storage/memory.js';
import type { SessionConfig } from '../src/types/config.js';
import type { Session, AdminUser, SessionMetadata } from '../src/types/auth.js';
import { makeClaim, makeFinalization } from './storage-conformance.js';


const testSessionConfig: SessionConfig = {
  maxAge: 7 * 24 * 60 * 60 * 1000, 
  cookieName: 'test_session',
  secureCookie: false,
  sameSite: 'lax',
  httpOnly: true,
  renewThreshold: 24 * 60 * 60 * 1000, 
  maxConcurrentSessions: 5,
  rememberMeDuration: 30 * 24 * 60 * 60 * 1000,
};

const testUser: Omit<AdminUser, 'id'> = {
  handle: 'testuser',
  email: 'test@example.com',
  passwordHash: '$2b$12$fakehash',
  totpEnabled: false,
  role: 'admin',
  isActive: true,
  needsOnboarding: false,
  onboardingStep: 0,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

const testMetadata: SessionMetadata = {
  clientIp: '192.168.1.1',
  clientIpMasked: '192.168.*.*',
  userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0',
  deviceType: 'desktop',
};

describe('SessionManager', () => {
  let storage: MemoryStorageAdapter;
  let sessionManager: SessionManager;
  let userId: string;

  beforeEach(async () => {
    storage = new MemoryStorageAdapter();
    await storage.init();
    sessionManager = new SessionManager({ storage, config: testSessionConfig });

    const claim = makeClaim();
    await storage.claimFirstUserBootstrap(claim);
    await storage.finalizeFirstUserBootstrap(makeFinalization(claim));
    const user = await storage.createUser(testUser);
    userId = user.id;
  });

  describe('createSession', () => {
    it('should create a session with correct user data', async () => {
      const session = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' }, testMetadata);

      expect(session).toBeDefined();
      expect(session.id).toBeTruthy();
      expect(session.userId).toBe(userId);
      expect(session.user?.role).toBe('admin');
      expect(session.clientIp).toBe('192.168.1.1');
      expect(session.userAgent).toContain('Chrome');
    });

    it('should generate a unique session ID', async () => {
      const session1 = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });
      const session2 = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });

      
      expect(session1.id).not.toBe(session2.id);
    });

    it('should set expiration date in the future', async () => {
      const session = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });

      const expires = new Date(session.expires);
      expect(expires.getTime()).toBeGreaterThan(Date.now());
    });

    it('should remove existing sessions for the same user (single session strategy)', async () => {
      const session1 = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });

      
      const session2 = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });

      
      const retrieved1 = await sessionManager.getSession(session1.id);
      expect(retrieved1).toBeNull();

      
      const retrieved2 = await sessionManager.getSession(session2.id);
      expect(retrieved2).not.toBeNull();
      expect(retrieved2?.id).toBe(session2.id);
    });

    it('should include metadata when provided', async () => {
      const session = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' }, testMetadata);

      expect(session.clientIp).toBe('192.168.1.1');
      expect(session.deviceType).toBe('desktop');
      expect(session.userAgent).toContain('Chrome');
    });

    it('should use default values when no metadata provided', async () => {
      const session = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });

      expect(session.clientIp).toBe('unknown');
      expect(session.userAgent).toBe('unknown');
    });
  });

  describe('getSession', () => {
    it('should retrieve a valid session by ID', async () => {
      const created = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });
      const retrieved = await sessionManager.getSession(created.id);

      expect(retrieved).not.toBeNull();
      expect(retrieved?.id).toBe(created.id);
      expect(retrieved?.userId).toBe(userId);
    });

    it('should return null for non-existent session', async () => {
      const retrieved = await sessionManager.getSession('non-existent-id');
      expect(retrieved).toBeNull();
    });

    it('should return null for empty session ID', async () => {
      const retrieved = await sessionManager.getSession('');
      expect(retrieved).toBeNull();
    });

    it('should return null and delete expired sessions', async () => {
      const created = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });

      
      await storage.updateSession(created.id, {
        expires: new Date(Date.now() - 1000).toISOString(),
      });

      const retrieved = await sessionManager.getSession(created.id);
      expect(retrieved).toBeNull();
    });
  });

  describe('validateSession', () => {
    it('should return session for valid session ID', async () => {
      const created = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });
      const validated = await sessionManager.validateSession(created.id);

      expect(validated).not.toBeNull();
      expect(validated?.id).toBe(created.id);
    });

    it('should return null for invalid session ID', async () => {
      const validated = await sessionManager.validateSession('invalid');
      expect(validated).toBeNull();
    });
  });

  describe('updateSession', () => {
    it('should update session fields', async () => {
      const created = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });

      const updated = await sessionManager.updateSession(created.id, {
        deviceType: 'mobile',
      });

      expect(updated.deviceType).toBe('mobile');
      expect(updated.id).toBe(created.id);
    });

    it('should not overwrite session ID', async () => {
      const created = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });

      const updated = await sessionManager.updateSession(created.id, {
        id: 'attempted-id-override',
      } as Partial<Session>);

      expect(updated.id).toBe(created.id);
    });
  });

  describe('updateSessionUser', () => {
    it('should update user data within session', async () => {
      const created = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });

      const result = await sessionManager.updateSessionUser(created.id, {
        role: 'super_admin',
      });

      expect(result).toBe(true);

      const retrieved = await sessionManager.getSession(created.id);
      expect(retrieved?.user?.role).toBe('super_admin');
    });

    it('should return false for non-existent session', async () => {
      const result = await sessionManager.updateSessionUser('non-existent', {
        role: 'admin',
      });

      expect(result).toBe(false);
    });
  });

  describe('refreshSession', () => {
    it('should extend session expiry', async () => {
      const created = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });
      const originalExpiry = new Date(created.expires).getTime();

      
      await new Promise(resolve => setTimeout(resolve, 10));

      const refreshed = await sessionManager.refreshSession(created.id);

      expect(refreshed).not.toBeNull();
      const newExpiry = new Date(refreshed!.expires).getTime();
      expect(newExpiry).toBeGreaterThanOrEqual(originalExpiry);
    });

    it('should return null for non-existent session', async () => {
      const result = await sessionManager.refreshSession('non-existent');
      expect(result).toBeNull();
    });
  });

  describe('removeSession', () => {
    it('should delete an existing session', async () => {
      const created = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });

      const deleted = await sessionManager.removeSession(created.id);
      expect(deleted).toBe(true);

      const retrieved = await sessionManager.getSession(created.id);
      expect(retrieved).toBeNull();
    });

    it('should return false when deleting non-existent session', async () => {
      const deleted = await sessionManager.removeSession('non-existent');
      expect(deleted).toBe(false);
    });
  });

  describe('removeUserSessions', () => {
    it('should remove all sessions for a user', async () => {
      
      await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });

      const count = await sessionManager.removeUserSessions(userId);
      expect(count).toBeGreaterThanOrEqual(1);

      const sessions = await sessionManager.getUserSessions(userId);
      expect(sessions).toHaveLength(0);
    });

    it('should return 0 for user with no sessions', async () => {
      const count = await sessionManager.removeUserSessions('no-sessions-user');
      expect(count).toBe(0);
    });
  });

  describe('cleanupExpiredSessions', () => {
    it('should remove expired sessions', async () => {
      const created = await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });

      
      await storage.updateSession(created.id, {
        expires: new Date(Date.now() - 1000).toISOString(),
      });

      const cleaned = await sessionManager.cleanupExpiredSessions();
      expect(cleaned).toBeGreaterThanOrEqual(1);
    });

    it('should not remove valid sessions', async () => {
      await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });

      const cleaned = await sessionManager.cleanupExpiredSessions();
      expect(cleaned).toBe(0);
    });
  });

  describe('getUserSessions', () => {
    it('should return active sessions for a user', async () => {
      await sessionManager.createSession(userId, { handle: 'testuser', role: 'admin' });

      const sessions = await sessionManager.getUserSessions(userId);
      expect(sessions.length).toBeGreaterThanOrEqual(1);
      expect(sessions[0].userId).toBe(userId);
    });

    it('should return empty array for user with no sessions', async () => {
      const sessions = await sessionManager.getUserSessions('no-sessions-user');
      expect(sessions).toHaveLength(0);
    });
  });

  describe('shouldRenewSession', () => {
    it('should return true when session is close to expiry', () => {
      const nearExpiry: Session = {
        id: 'test',
        userId: 'user-1',
        expires: new Date(Date.now() + 1000).toISOString(), 
        expiresAt: new Date(Date.now() + 1000).toISOString(),
        createdAt: new Date().toISOString(),
        clientIp: '127.0.0.1',
        userAgent: 'test',
      };

      expect(sessionManager.shouldRenewSession(nearExpiry)).toBe(true);
    });

    it('should return false when session has plenty of time left', () => {
      const freshSession: Session = {
        id: 'test',
        userId: 'user-1',
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), 
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date().toISOString(),
        clientIp: '127.0.0.1',
        userAgent: 'test',
      };

      expect(sessionManager.shouldRenewSession(freshSession)).toBe(false);
    });
  });

  describe('isSessionValid', () => {
    it('should return true for non-expired session', () => {
      const validSession: Session = {
        id: 'test',
        userId: 'user-1',
        expires: new Date(Date.now() + 60000).toISOString(),
        expiresAt: new Date(Date.now() + 60000).toISOString(),
        createdAt: new Date().toISOString(),
        clientIp: '127.0.0.1',
        userAgent: 'test',
      };

      expect(sessionManager.isSessionValid(validSession)).toBe(true);
    });

    it('should return false for expired session', () => {
      const expiredSession: Session = {
        id: 'test',
        userId: 'user-1',
        expires: new Date(Date.now() - 1000).toISOString(),
        expiresAt: new Date(Date.now() - 1000).toISOString(),
        createdAt: new Date().toISOString(),
        clientIp: '127.0.0.1',
        userAgent: 'test',
      };

      expect(sessionManager.isSessionValid(expiredSession)).toBe(false);
    });

    it('should return false for null session', () => {
      expect(sessionManager.isSessionValid(null)).toBe(false);
    });
  });
});

describe('createSessionManager', () => {
  it('should create a SessionManager instance', async () => {
    const storage = new MemoryStorageAdapter();
    await storage.init();
    const manager = createSessionManager(storage, testSessionConfig);
    expect(manager).toBeInstanceOf(SessionManager);
  });
});

describe('classifyDevice', () => {
  it('should classify mobile user agents', () => {
    expect(classifyDevice('Mozilla/5.0 (iPhone; CPU iPhone OS 16_0)')).toBe('mobile');
    expect(classifyDevice('Mozilla/5.0 (Linux; Android 13; Pixel 7) Mobile')).toBe('mobile');
  });

  it('should classify tablet user agents', () => {
    expect(classifyDevice('Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X)')).toBe('tablet');
  });

  it('should classify desktop user agents', () => {
    expect(classifyDevice('Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0')).toBe('desktop');
    expect(classifyDevice('Mozilla/5.0 (Windows NT 10.0; Win64) Firefox/120.0')).toBe('desktop');
  });

  it('should return unknown for unrecognized user agents', () => {
    expect(classifyDevice('curl/7.88.0')).toBe('unknown');
    expect(classifyDevice('')).toBe('unknown');
  });
});

describe('extractBrowserInfo', () => {
  it('should detect Chrome browser', () => {
    const info = extractBrowserInfo('Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0 Safari/537.36');
    expect(info.browser).toBe('Chrome');
    expect(info.platform).toBe('Linux');
  });

  it('should detect Firefox browser', () => {
    const info = extractBrowserInfo('Mozilla/5.0 (Windows NT 10.0; Win64) Gecko/20100101 Firefox/120.0');
    expect(info.browser).toBe('Firefox');
    expect(info.platform).toBe('Windows');
  });

  it('should detect Safari browser', () => {
    const info = extractBrowserInfo('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1 Version/17 Safari/605.1');
    expect(info.browser).toBe('Safari');
    expect(info.platform).toBe('macOS');
  });

  it('should return Unknown for unrecognized browsers', () => {
    const info = extractBrowserInfo('custom-bot/1.0');
    expect(info.browser).toBe('Unknown');
    expect(info.platform).toBe('Unknown');
  });
});
