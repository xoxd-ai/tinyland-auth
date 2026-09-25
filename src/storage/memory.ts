








import { randomUUID } from 'crypto';
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
import {
  FirstUserBootstrapConflictError,
  canonicalizeFirstUserBootstrapFinalization,
  canonicalizeFirstUserBootstrapFinalizationPayload,
  canonicalizeInertFirstUserClaim,
  canonicalizeStructuralInertFirstUserClaim,
  cloneBootstrapValue,
  createFirstUserBootstrapReceipt,
  firstUserBootstrapMaterialDigest,
  firstUserBootstrapValueDigest,
  isExpiredInertFirstUserClaim,
  normalizeFirstUserBootstrapTenantId,
  type FirstUserBootstrapFinalization,
  type FirstUserBootstrapReceipt,
  type InertFirstUserClaim,
} from './firstUserBootstrap.js';

export class MemoryStorageAdapter implements IStorageAdapter {
  private users = new Map<string, AdminUser>();
  private usersByHandle = new Map<string, string>(); 
  private usersByEmail = new Map<string, string>(); 
  private sessions = new Map<string, Session>();
  private totpSecrets = new Map<string, EncryptedTOTPSecret>();
  private backupCodes = new Map<string, BackupCodeSet>();
  private invitations = new Map<string, AdminInvitation>();
  private auditEvents: AuditEvent[] = [];
  private firstUserClaims = new Map<string, InertFirstUserClaim>();
  private firstUserFinalizations = new Map<string, FirstUserBootstrapFinalization>();
  private firstUserReceipts = new Map<string, FirstUserBootstrapReceipt>();

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
    this.firstUserClaims.clear();
    this.firstUserFinalizations.clear();
    this.firstUserReceipts.clear();
  }

  async claimFirstUserBootstrap(
    claim: InertFirstUserClaim,
  ): Promise<InertFirstUserClaim> {
    const structuralClaim = canonicalizeStructuralInertFirstUserClaim(claim);
    if (this.firstUserReceipts.has(structuralClaim.tenantId)) {
      throw new FirstUserBootstrapConflictError(
        'First-user bootstrap is already finalized for this tenant',
      );
    }

    const existing = this.firstUserClaims.get(structuralClaim.tenantId);
    if (existing) {
      if (
        firstUserBootstrapValueDigest(existing) ===
        firstUserBootstrapValueDigest(structuralClaim)
      ) {
        this.sessions.clear();
        return cloneBootstrapValue(existing);
      }
      if (!isExpiredInertFirstUserClaim(existing)) {
        throw new FirstUserBootstrapConflictError(
          'A different first-user bootstrap claim already exists for this tenant',
        );
      }
    }
    const canonicalClaim = canonicalizeInertFirstUserClaim(structuralClaim);
    if (this.firstUserClaims.size > (existing ? 1 : 0)) {
      throw new FirstUserBootstrapConflictError(
        'This memory storage instance already belongs to another bootstrap tenant',
      );
    }
    if (this.users.size > 0) {
      throw new FirstUserBootstrapConflictError(
        'First-user bootstrap requires an empty user store',
      );
    }
    if (
      this.totpSecrets.has(canonicalClaim.actor.handle.toLowerCase()) ||
      this.backupCodes.has(canonicalClaim.actor.id)
    ) {
      throw new FirstUserBootstrapConflictError(
        'Claimed actor already has factor state',
      );
    }

    this.sessions.clear();
    const stored = cloneBootstrapValue(canonicalClaim);
    this.firstUserClaims.set(canonicalClaim.tenantId, stored);
    return cloneBootstrapValue(stored);
  }

  async finalizeFirstUserBootstrap(
    finalization: FirstUserBootstrapFinalization,
  ): Promise<FirstUserBootstrapReceipt> {
    const payload = canonicalizeFirstUserBootstrapFinalizationPayload(finalization);
    const existingReceipt = this.firstUserReceipts.get(payload.tenantId);
    if (existingReceipt) {
      const existingClaim = this.firstUserClaims.get(payload.tenantId);
      const existingMaterial = this.firstUserFinalizations.get(payload.tenantId);
      if (!existingClaim || !existingMaterial) {
        throw new FirstUserBootstrapConflictError(
          'Bootstrap completion state is internally inconsistent',
        );
      }
      const canonicalReplay = canonicalizeFirstUserBootstrapFinalization(
        existingClaim,
        payload,
        Date.parse(existingMaterial.finalizedAt),
      );
      if (
        existingReceipt.attemptId === canonicalReplay.attemptId &&
        existingReceipt.materialDigest ===
          firstUserBootstrapMaterialDigest(canonicalReplay)
      ) {
        return cloneBootstrapValue(existingReceipt);
      }
      throw new FirstUserBootstrapConflictError(
        'Bootstrap finalization conflicts with the immutable completion receipt',
      );
    }

    const claim = this.firstUserClaims.get(payload.tenantId);
    if (!claim) {
      throw new FirstUserBootstrapConflictError(
        'No active first-user bootstrap claim exists for this tenant',
      );
    }
    const material = canonicalizeFirstUserBootstrapFinalization(claim, payload);
    if (this.users.size > 0) {
      throw new FirstUserBootstrapConflictError(
        'First-user bootstrap requires an empty user store',
      );
    }

    const receipt = createFirstUserBootstrapReceipt(claim, material);
    this.users.set(material.user.id, cloneBootstrapValue(material.user));
    this.usersByHandle.set(material.user.handle.toLowerCase(), material.user.id);
    if (material.user.email) {
      this.usersByEmail.set(material.user.email.toLowerCase(), material.user.id);
    }
    this.totpSecrets.set(
      material.user.handle.toLowerCase(),
      cloneBootstrapValue(material.totpSecret),
    );
    this.backupCodes.set(
      material.user.id,
      cloneBootstrapValue(material.backupCodes),
    );
    this.firstUserFinalizations.set(material.tenantId, cloneBootstrapValue(material));
    this.firstUserReceipts.set(material.tenantId, cloneBootstrapValue(receipt));
    return cloneBootstrapValue(receipt);
  }

  async getFirstUserBootstrapReceipt(
    tenantId: string,
  ): Promise<FirstUserBootstrapReceipt | null> {
    const receipt = this.firstUserReceipts.get(
      normalizeFirstUserBootstrapTenantId(tenantId),
    );
    return receipt ? cloneBootstrapValue(receipt) : null;
  }

  private getClaimedTenantForActor(
    actorId?: string,
    handle?: string,
  ): string | null {
    for (const [tenantId, claim] of this.firstUserClaims) {
      if (
        (actorId !== undefined && claim.actor.id === actorId) ||
        (handle !== undefined && claim.actor.handle.toLowerCase() === handle.toLowerCase())
      ) {
        return tenantId;
      }
    }
    return null;
  }

  private isFinalizedTenant(tenantId: string): boolean {
    return this.firstUserReceipts.has(tenantId);
  }

  
  
  

  async getUser(id: string): Promise<AdminUser | null> {
    const user = this.users.get(id);
    return user ? cloneBootstrapValue(user) : null;
  }

  async getUserByHandle(handle: string): Promise<AdminUser | null> {
    const userId = this.usersByHandle.get(handle.toLowerCase());
    if (!userId) return null;
    const user = this.users.get(userId);
    return user ? cloneBootstrapValue(user) : null;
  }

  async getUserByEmail(email: string): Promise<AdminUser | null> {
    const userId = this.usersByEmail.get(email.toLowerCase());
    if (!userId) return null;
    const user = this.users.get(userId);
    return user ? cloneBootstrapValue(user) : null;
  }

  async getAllUsers(): Promise<AdminUser[]> {
    return Array.from(this.users.values(), (user) => cloneBootstrapValue(user));
  }

  async createUser(user: Omit<AdminUser, 'id'>): Promise<AdminUser> {
    if (
      Array.from(this.firstUserClaims.keys()).some(
        (tenantId) => !this.isFinalizedTenant(tenantId),
      )
    ) {
      throw new FirstUserBootstrapConflictError(
        'Cannot create a user while a first-user bootstrap claim is active',
      );
    }
    const bootstrapReceipt =
      this.firstUserReceipts.size === 1
        ? this.firstUserReceipts.values().next().value
        : undefined;
    if (!bootstrapReceipt || !this.users.has(bootstrapReceipt.userId)) {
      throw new FirstUserBootstrapConflictError(
        'Ordinary user creation requires a finalized first-user bootstrap receipt',
      );
    }
    const id = randomUUID();
    const newUser: AdminUser = { ...user, id };

    this.users.set(id, cloneBootstrapValue(newUser));
    this.usersByHandle.set(newUser.handle.toLowerCase(), id);
    if (newUser.email) {
      this.usersByEmail.set(newUser.email.toLowerCase(), id);
    }

    return cloneBootstrapValue(newUser);
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

    this.users.set(id, cloneBootstrapValue(updatedUser));
    return cloneBootstrapValue(updatedUser);
  }

  async deleteUser(id: string): Promise<boolean> {
    const bootstrapTenant = this.getClaimedTenantForActor(id);
    if (bootstrapTenant) {
      throw new FirstUserBootstrapConflictError(
        this.isFinalizedTenant(bootstrapTenant)
          ? 'Cannot delete a bootstrap-finalized actor'
          : 'Cannot delete a claimed first-user actor',
      );
    }

    const user = this.users.get(id);
    if (!user) return false;

    await this.deleteUserSessions(id);
    await this.deleteTOTPSecret(user.handle);
    await this.deleteBackupCodes(id);

    this.users.delete(id);
    this.usersByHandle.delete(user.handle.toLowerCase());
    if (user.email) {
      this.usersByEmail.delete(user.email.toLowerCase());
    }

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

    return cloneBootstrapValue(session);
  }

  async getSessionsByUser(userId: string): Promise<Session[]> {
    const now = new Date();
    return Array.from(this.sessions.values())
      .filter(s => s.userId === userId && new Date(s.expires) > now)
      .map((session) => cloneBootstrapValue(session));
  }

  async getAllSessions(): Promise<Session[]> {
    return Array.from(this.sessions.values()).map((session) =>
      cloneBootstrapValue(session),
    );
  }

  async createSession(
    userId: string,
    user: Partial<AdminUser>,
    metadata?: SessionMetadata
  ): Promise<Session> {
    if (user.id !== undefined && user.id !== userId) {
      throw new FirstUserBootstrapConflictError(
        'Session user identity does not match userId',
      );
    }
    const hasActiveBootstrapClaim = Array.from(this.firstUserClaims.keys()).some(
      (tenantId) => !this.isFinalizedTenant(tenantId),
    );
    if (hasActiveBootstrapClaim) {
      throw new FirstUserBootstrapConflictError(
        'session authority is unavailable while first-user bootstrap is claimed',
      );
    }
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

    this.sessions.set(id, cloneBootstrapValue(session));
    return cloneBootstrapValue(session);
  }

  async updateSession(id: string, updates: Partial<Session>): Promise<Session> {
    const session = this.sessions.get(id);
    if (!session) {
      throw new Error(`Session ${id} not found`);
    }

    if (updates.userId !== undefined && updates.userId !== session.userId) {
      throw new FirstUserBootstrapConflictError(
        'Session user identity is immutable',
      );
    }
    const currentNestedUserId = session.user?.id ?? session.userId;
    if (
      updates.user?.id !== undefined &&
      updates.user.id !== currentNestedUserId
    ) {
      throw new FirstUserBootstrapConflictError(
        'Nested session user identity is immutable',
      );
    }

    const updatedSession: Session = {
      ...session,
      ...cloneBootstrapValue(updates),
      id,
      userId: session.userId,
    };

    this.sessions.set(id, cloneBootstrapValue(updatedSession));
    return cloneBootstrapValue(updatedSession);
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
    const secret = this.totpSecrets.get(handle.toLowerCase());
    return secret ? cloneBootstrapValue(secret) : null;
  }

  async saveTOTPSecret(handle: string, secret: EncryptedTOTPSecret): Promise<void> {
    const bootstrapTenant = this.getClaimedTenantForActor(secret.userId, handle);
    if (bootstrapTenant && !this.isFinalizedTenant(bootstrapTenant)) {
      throw new FirstUserBootstrapConflictError(
        'Cannot enroll TOTP for a claimed actor before finalization',
      );
    }
    this.totpSecrets.set(handle.toLowerCase(), cloneBootstrapValue(secret));
  }

  async deleteTOTPSecret(handle: string): Promise<boolean> {
    const bootstrapTenant = this.getClaimedTenantForActor(undefined, handle);
    if (bootstrapTenant) {
      throw new FirstUserBootstrapConflictError(
        'Cannot delete a claimed or bootstrap-finalized TOTP factor',
      );
    }
    return this.totpSecrets.delete(handle.toLowerCase());
  }

  
  
  

  async getBackupCodes(userId: string): Promise<BackupCodeSet | null> {
    const codes = this.backupCodes.get(userId);
    return codes ? cloneBootstrapValue(codes) : null;
  }

  async saveBackupCodes(userId: string, codes: BackupCodeSet): Promise<void> {
    const bootstrapTenant = this.getClaimedTenantForActor(userId);
    if (bootstrapTenant && !this.isFinalizedTenant(bootstrapTenant)) {
      throw new FirstUserBootstrapConflictError(
        'Cannot save backup codes for a claimed actor before finalization',
      );
    }
    this.backupCodes.set(userId, cloneBootstrapValue(codes));
  }

  async deleteBackupCodes(userId: string): Promise<boolean> {
    const bootstrapTenant = this.getClaimedTenantForActor(userId);
    if (bootstrapTenant) {
      throw new FirstUserBootstrapConflictError(
        'Cannot delete claimed or bootstrap-finalized backup codes',
      );
    }
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
