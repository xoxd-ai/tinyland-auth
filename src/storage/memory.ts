








import { randomUUID } from 'crypto';
import type { BoundedSessionPolicy } from '../types/config.js';
import { assertBoundedSessionPolicy, boundedSessions } from './session-policy.js';
import type {
  IStorageAdapter,
  AuditEventFilters,
} from './interface.js';
import type {
  AdminUser,
  Session,
  SessionMetadata,
  EncryptedTOTPSecret,
  BackupCodeSet,
  AdminInvitation,
  AuditEvent,
} from '../types/auth.js';

export class MemoryStorageAdapter implements IStorageAdapter {
  private users = new Map<string, AdminUser>();
  private usersByHandle = new Map<string, string>(); 
  private usersByEmail = new Map<string, string>(); 
  private sessions = new Map<string, Session>();
  private totpSecrets = new Map<string, EncryptedTOTPSecret>();
  private backupCodes = new Map<string, BackupCodeSet>();
  private invitations = new Map<string, AdminInvitation>();
  private auditEvents: AuditEvent[] = [];

  async init(): Promise<void> {
    
  }

  async close(): Promise<void> {
    
    this.users.clear();
    this.usersByHandle.clear();
    this.usersByEmail.clear();
    this.sessions.clear();
    this.totpSecrets.clear();
    this.backupCodes.clear();
    this.invitations.clear();
    this.auditEvents = [];
  }

  
  
  

  async getUser(id: string): Promise<AdminUser | null> {
    return this.users.get(id) || null;
  }

  async getUserByHandle(handle: string): Promise<AdminUser | null> {
    const userId = this.usersByHandle.get(handle.toLowerCase());
    if (!userId) return null;
    return this.users.get(userId) || null;
  }

  async getUserByEmail(email: string): Promise<AdminUser | null> {
    const userId = this.usersByEmail.get(email.toLowerCase());
    if (!userId) return null;
    return this.users.get(userId) || null;
  }

  async getAllUsers(): Promise<AdminUser[]> {
    return Array.from(this.users.values());
  }

  async createUser(user: Omit<AdminUser, 'id'>): Promise<AdminUser> {
    const id = randomUUID();
    const newUser: AdminUser = { ...user, id };

    this.users.set(id, newUser);
    this.usersByHandle.set(newUser.handle.toLowerCase(), id);
    if (newUser.email) {
      this.usersByEmail.set(newUser.email.toLowerCase(), id);
    }

    return newUser;
  }

  async updateUser(id: string, updates: Partial<AdminUser>): Promise<AdminUser> {
    const user = this.users.get(id);
    if (!user) {
      throw new Error(`User ${id} not found`);
    }

    
    if (updates.handle && updates.handle !== user.handle) {
      this.usersByHandle.delete(user.handle.toLowerCase());
      this.usersByHandle.set(updates.handle.toLowerCase(), id);
    }
    if (updates.email && updates.email !== user.email) {
      if (user.email) {
        this.usersByEmail.delete(user.email.toLowerCase());
      }
      this.usersByEmail.set(updates.email.toLowerCase(), id);
    }

    const updatedUser: AdminUser = {
      ...user,
      ...updates,
      id, 
      updatedAt: new Date().toISOString(),
    };

    this.users.set(id, updatedUser);
    return updatedUser;
  }

  async deleteUser(id: string): Promise<boolean> {
    const user = this.users.get(id);
    if (!user) return false;

    this.users.delete(id);
    this.usersByHandle.delete(user.handle.toLowerCase());
    if (user.email) {
      this.usersByEmail.delete(user.email.toLowerCase());
    }

    
    await this.deleteUserSessions(id);
    await this.deleteTOTPSecret(user.handle);
    await this.deleteBackupCodes(id);

    return true;
  }

  async hasUsers(): Promise<boolean> {
    return this.users.size > 0;
  }

  
  
  

  async getSession(id: string): Promise<Session | null> {
    const session = this.sessions.get(id);
    if (!session) return null;

    
    if (new Date(session.expires) < new Date()) {
      this.sessions.delete(id);
      return null;
    }

    return session;
  }

  async getSessionsByUser(userId: string): Promise<Session[]> {
    const now = new Date();
    return Array.from(this.sessions.values())
      .filter(s => s.userId === userId && new Date(s.expires) > now);
  }

  async getAllSessions(): Promise<Session[]> {
    return Array.from(this.sessions.values());
  }

  async createSession(
    userId: string,
    user: Partial<AdminUser>,
    metadata?: SessionMetadata
  ): Promise<Session> {
    const session = this.newSession(userId, user, metadata);
    this.sessions.set(session.id, session);
    return session;
  }

  async createSessionWithPolicy(
    userId: string,
    user: Partial<AdminUser>,
    metadata: SessionMetadata | undefined,
    policy: BoundedSessionPolicy,
  ): Promise<Session> {
    assertBoundedSessionPolicy(policy);
    // No await between reading and replacing this adapter's session map.
    const session = this.newSession(userId, user, metadata);
    const next = boundedSessions([...this.sessions.values()], session, policy, Date.now());
    this.sessions = new Map(next.map((item) => [item.id, item]));
    return session;
  }

  private newSession(
    userId: string, user: Partial<AdminUser>, metadata?: SessionMetadata,
  ): Session {
    const id = randomUUID();
    const now = new Date();
    const expires = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); 

    const session: Session = {
      id,
      userId,
      expires: expires.toISOString(),
      expiresAt: expires.toISOString(),
      createdAt: now.toISOString(),
      user: {
        id: user.id || userId,
        username: user.handle || '',
        name: user.displayName || user.handle || '',
        role: user.role || 'viewer',
        needsOnboarding: user.needsOnboarding,
        onboardingStep: user.onboardingStep,
      },
      clientIp: metadata?.clientIp || 'unknown',
      clientIpMasked: metadata?.clientIpMasked,
      userAgent: metadata?.userAgent || 'unknown',
      deviceType: metadata?.deviceType || 'unknown',
      browserFingerprint: metadata?.browserFingerprint,
      geoLocation: metadata?.geoLocation,
    };

    return session;
  }

  async updateSession(id: string, updates: Partial<Session>): Promise<Session> {
    const session = this.sessions.get(id);
    if (!session) {
      throw new Error(`Session ${id} not found`);
    }

    const updatedSession: Session = {
      ...session,
      ...updates,
      id, 
    };

    this.sessions.set(id, updatedSession);
    return updatedSession;
  }

  async deleteSession(id: string): Promise<boolean> {
    return this.sessions.delete(id);
  }

  async deleteUserSessions(userId: string): Promise<number> {
    let count = 0;
    for (const [id, session] of this.sessions.entries()) {
      if (session.userId === userId) {
        this.sessions.delete(id);
        count++;
      }
    }
    return count;
  }

  async cleanupExpiredSessions(): Promise<number> {
    const now = new Date();
    let count = 0;
    for (const [id, session] of this.sessions.entries()) {
      if (new Date(session.expires) < now) {
        this.sessions.delete(id);
        count++;
      }
    }
    return count;
  }

  
  
  

  async getTOTPSecret(handle: string): Promise<EncryptedTOTPSecret | null> {
    return this.totpSecrets.get(handle.toLowerCase()) || null;
  }

  async saveTOTPSecret(handle: string, secret: EncryptedTOTPSecret): Promise<void> {
    this.totpSecrets.set(handle.toLowerCase(), secret);
  }

  async deleteTOTPSecret(handle: string): Promise<boolean> {
    return this.totpSecrets.delete(handle.toLowerCase());
  }

  
  
  

  async getBackupCodes(userId: string): Promise<BackupCodeSet | null> {
    return this.backupCodes.get(userId) || null;
  }

  async saveBackupCodes(userId: string, codes: BackupCodeSet): Promise<void> {
    this.backupCodes.set(userId, codes);
  }

  async deleteBackupCodes(userId: string): Promise<boolean> {
    return this.backupCodes.delete(userId);
  }

  
  
  

  async getInvitation(token: string): Promise<AdminInvitation | null> {
    const invitation = this.invitations.get(token);
    if (!invitation) return null;

    
    if (new Date(invitation.expiresAt) < new Date()) {
      return null;
    }

    return invitation;
  }

  async getInvitationById(id: string): Promise<AdminInvitation | null> {
    for (const invitation of this.invitations.values()) {
      if (invitation.id === id) {
        return invitation;
      }
    }
    return null;
  }

  async getAllInvitations(): Promise<AdminInvitation[]> {
    return Array.from(this.invitations.values());
  }

  async getPendingInvitations(): Promise<AdminInvitation[]> {
    const now = new Date();
    return Array.from(this.invitations.values())
      .filter(i => new Date(i.expiresAt) > now && !i.usedAt);
  }

  async createInvitation(invitation: Omit<AdminInvitation, 'id'>): Promise<AdminInvitation> {
    const id = randomUUID();
    const newInvitation: AdminInvitation = { ...invitation, id };

    this.invitations.set(invitation.token, newInvitation);
    return newInvitation;
  }

  async updateInvitation(token: string, updates: Partial<AdminInvitation>): Promise<AdminInvitation> {
    const invitation = this.invitations.get(token);
    if (!invitation) {
      throw new Error(`Invitation not found`);
    }

    const updatedInvitation: AdminInvitation = {
      ...invitation,
      ...updates,
    };

    this.invitations.set(token, updatedInvitation);
    return updatedInvitation;
  }

  async deleteInvitation(token: string): Promise<boolean> {
    return this.invitations.delete(token);
  }

  async cleanupExpiredInvitations(): Promise<number> {
    const now = new Date();
    let count = 0;
    for (const [token, invitation] of this.invitations.entries()) {
      if (new Date(invitation.expiresAt) < now || invitation.usedAt) {
        this.invitations.delete(token);
        count++;
      }
    }
    return count;
  }

  
  
  

  async logAuditEvent(event: Omit<AuditEvent, 'id'>): Promise<AuditEvent> {
    const id = `evt_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const auditEvent: AuditEvent = { ...event, id };

    this.auditEvents.push(auditEvent);

    
    if (this.auditEvents.length > 10000) {
      this.auditEvents = this.auditEvents.slice(-10000);
    }

    return auditEvent;
  }

  async getAuditEvents(filters: AuditEventFilters): Promise<AuditEvent[]> {
    let events = [...this.auditEvents];

    if (filters.type) {
      events = events.filter(e => e.type === filters.type);
    }
    if (filters.userId) {
      events = events.filter(e => e.userId === filters.userId);
    }
    if (filters.severity) {
      events = events.filter(e => e.severity === filters.severity);
    }
    if (filters.startDate) {
      events = events.filter(e => new Date(e.timestamp) >= filters.startDate!);
    }
    if (filters.endDate) {
      events = events.filter(e => new Date(e.timestamp) <= filters.endDate!);
    }

    if (filters.offset) {
      events = events.slice(filters.offset);
    }
    if (filters.limit) {
      events = events.slice(0, filters.limit);
    }

    return events;
  }

  async getRecentAuditEvents(limit: number = 100): Promise<AuditEvent[]> {
    return this.auditEvents.slice(-limit).reverse();
  }
}
