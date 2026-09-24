







import type { Session, SessionMetadata, SessionUser, AdminUser, SessionConfig } from '../../types/index.js';
import type { SessionStorage } from '../../storage/interface.js';
import { assertBoundedSessionPolicy } from '../../storage/session-policy.js';

export interface SessionManagerConfig {
  storage: SessionStorage;
  config: SessionConfig;
}

export class SessionManager {
  private storage: SessionStorage;
  private config: SessionConfig;

  constructor({ storage, config }: SessionManagerConfig) {
    this.storage = storage;
    this.config = config;
  }

  


  async createSession(
    userId: string,
    user: Partial<AdminUser>,
    metadata?: SessionMetadata
  ): Promise<Session> {
    if (this.config.sessionStrategy === 'bounded') {
      const policy = {
        maxConcurrentSessions: this.config.maxConcurrentSessions,
        overflow: 'evict-oldest-created' as const,
      };
      assertBoundedSessionPolicy(policy);
      if (!this.storage.createSessionWithPolicy) {
        throw new Error('Storage does not support atomic bounded sessions');
      }
      return this.storage.createSessionWithPolicy(userId, user, metadata, policy);
    }
    if (this.config.sessionStrategy !== undefined && this.config.sessionStrategy !== 'single') {
      throw new Error('Invalid session strategy');
    }

    await this.storage.deleteUserSessions(userId);

    const session = await this.storage.createSession(userId, user, metadata);
    return session;
  }

  


  async getSession(sessionId: string): Promise<Session | null> {
    if (!sessionId) return null;

    const session = await this.storage.getSession(sessionId);
    if (!session) return null;

    
    if (new Date(session.expires) < new Date()) {
      await this.storage.deleteSession(sessionId);
      return null;
    }

    return session;
  }

  


  async validateSession(sessionId: string): Promise<Session | null> {
    return this.getSession(sessionId);
  }

  


  async updateSession(sessionId: string, updates: Partial<Session>): Promise<Session> {
    return this.storage.updateSession(sessionId, updates);
  }

  


  async updateSessionUser(sessionId: string, userData: Partial<SessionUser>): Promise<boolean> {
    const session = await this.getSession(sessionId);
    if (!session) return false;

    const updatedUser: SessionUser = {
      ...session.user,
      ...userData,
      id: session.user?.id || session.userId,
    } as SessionUser;

    await this.storage.updateSession(sessionId, { user: updatedUser });
    return true;
  }

  


  async refreshSession(sessionId: string): Promise<Session | null> {
    const session = await this.getSession(sessionId);
    if (!session) return null;

    const now = new Date();
    const newExpiry = new Date(now.getTime() + this.config.maxAge);

    return this.storage.updateSession(sessionId, {
      expires: newExpiry.toISOString(),
      expiresAt: newExpiry.toISOString(),
    });
  }

  


  async removeSession(sessionId: string): Promise<boolean> {
    return this.storage.deleteSession(sessionId);
  }

  


  async removeUserSessions(userId: string): Promise<number> {
    return this.storage.deleteUserSessions(userId);
  }

  


  async cleanupExpiredSessions(): Promise<number> {
    return this.storage.cleanupExpiredSessions();
  }

  


  async getUserSessions(userId: string): Promise<Session[]> {
    return this.storage.getSessionsByUser(userId);
  }

  


  shouldRenewSession(session: Session): boolean {
    const expires = new Date(session.expires);
    const now = new Date();
    const remaining = expires.getTime() - now.getTime();
    return remaining < this.config.renewThreshold;
  }

  


  isSessionValid(session: Session | null): session is Session {
    if (!session) return false;
    return new Date(session.expires) > new Date();
  }
}




export function createSessionManager(
  storage: SessionStorage,
  config: SessionConfig
): SessionManager {
  return new SessionManager({ storage, config });
}




export function classifyDevice(userAgent: string): 'mobile' | 'tablet' | 'desktop' | 'unknown' {
  const ua = userAgent.toLowerCase();

  if (/mobile|android|iphone|ipod|blackberry|opera mini|iemobile/i.test(ua)) {
    
    if (/tablet|ipad|android(?!.*mobile)/i.test(ua)) {
      return 'tablet';
    }
    return 'mobile';
  }

  if (/tablet|ipad/i.test(ua)) {
    return 'tablet';
  }

  if (/mozilla|chrome|safari|firefox|edge|opera/i.test(ua)) {
    return 'desktop';
  }

  return 'unknown';
}








export {
  createActivityTracker,
  type ActivityTrackingConfig,
  type ActivityType,
  type ActivityEvent,
} from './activity-tracking.js';




export function extractBrowserInfo(userAgent: string): { browser: string; platform: string } {
  const ua = userAgent.toLowerCase();

  let browser = 'Unknown';
  let platform = 'Unknown';

  
  if (ua.includes('firefox')) browser = 'Firefox';
  else if (ua.includes('edg')) browser = 'Edge';
  else if (ua.includes('chrome')) browser = 'Chrome';
  else if (ua.includes('safari')) browser = 'Safari';
  else if (ua.includes('opera')) browser = 'Opera';

  
  if (ua.includes('windows')) platform = 'Windows';
  else if (ua.includes('mac')) platform = 'macOS';
  else if (ua.includes('linux')) platform = 'Linux';
  else if (ua.includes('android')) platform = 'Android';
  else if (ua.includes('iphone') || ua.includes('ipad')) platform = 'iOS';

  return { browser, platform };
}
