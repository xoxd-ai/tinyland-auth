








import type {
  AdminUser,
  Session,
  SessionMetadata,
  EncryptedTOTPSecret,
  BackupCodeSet,
  AdminInvitation,
  AuditEvent,
} from '../types/auth.js';
import type {
  FirstUserBootstrapFinalization,
  FirstUserBootstrapReceipt,
  InertFirstUserClaim,
} from './firstUserBootstrap.js';






/**
 * Storage contract for one auth tenant.
 *
 * `claimFirstUserBootstrap`, `finalizeFirstUserBootstrap`, and `createUser`
 * share one atomic authority boundary. Implementations must not allow
 * `createUser` to insert a user until this same storage boundary contains a
 * valid finalized first-user receipt and its user. The receipt check and user
 * insertion must be one transaction or equivalent serialization operation. A
 * storage-native migration marker may reconcile a non-empty store created by a
 * pre-protocol release, but it must select legacy ownership fail-closed and
 * must never authorize an empty store.
 * Accepting a claim must revoke all sessions already present in this tenant
 * boundary, and `createSession` must reject every caller until finalization.
 */
export interface IStorageAdapter {
  claimFirstUserBootstrap(
    claim: InertFirstUserClaim,
  ): Promise<InertFirstUserClaim>;

  finalizeFirstUserBootstrap(
    finalization: FirstUserBootstrapFinalization,
  ): Promise<FirstUserBootstrapReceipt>;

  getFirstUserBootstrapReceipt(
    tenantId: string,
  ): Promise<FirstUserBootstrapReceipt | null>;
  
  
  

  


  getUser(id: string): Promise<AdminUser | null>;

  


  getUserByHandle(handle: string): Promise<AdminUser | null>;

  


  getUserByEmail(email: string): Promise<AdminUser | null>;

  


  getAllUsers(): Promise<AdminUser[]>;

  


  /**
   * Creates an ordinary post-bootstrap user.
   *
   * This must fail closed before first-user finalization, except for a
   * storage-native reconciliation of a non-empty pre-protocol store. A
   * separate `hasUsers()` or receipt preflight is not sufficient because it
   * races bootstrap finalization.
   */
  createUser(user: Omit<AdminUser, 'id'>): Promise<AdminUser>;

  


  updateUser(id: string, updates: Partial<AdminUser>): Promise<AdminUser>;

  


  deleteUser(id: string): Promise<boolean>;

  


  hasUsers(): Promise<boolean>;

  
  
  

  


  getSession(id: string): Promise<Session | null>;

  


  getSessionsByUser(userId: string): Promise<Session[]>;

  


  getAllSessions(): Promise<Session[]>;

  


  createSession(
    userId: string,
    user: Partial<AdminUser>,
    metadata?: SessionMetadata
  ): Promise<Session>;

  


  updateSession(id: string, updates: Partial<Session>): Promise<Session>;

  


  deleteSession(id: string): Promise<boolean>;

  


  deleteUserSessions(userId: string): Promise<number>;

  


  cleanupExpiredSessions(): Promise<number>;

  
  
  

  


  getTOTPSecret(handle: string): Promise<EncryptedTOTPSecret | null>;

  


  saveTOTPSecret(handle: string, secret: EncryptedTOTPSecret): Promise<void>;

  


  deleteTOTPSecret(handle: string): Promise<boolean>;

  
  
  

  


  getBackupCodes(userId: string): Promise<BackupCodeSet | null>;

  


  saveBackupCodes(userId: string, codes: BackupCodeSet): Promise<void>;

  


  deleteBackupCodes(userId: string): Promise<boolean>;

  
  
  

  


  getInvitation(token: string): Promise<AdminInvitation | null>;

  


  getInvitationById(id: string): Promise<AdminInvitation | null>;

  


  getAllInvitations(): Promise<AdminInvitation[]>;

  


  getPendingInvitations(): Promise<AdminInvitation[]>;

  


  createInvitation(invitation: Omit<AdminInvitation, 'id'>): Promise<AdminInvitation>;

  


  updateInvitation(token: string, updates: Partial<AdminInvitation>): Promise<AdminInvitation>;

  


  deleteInvitation(token: string): Promise<boolean>;

  


  cleanupExpiredInvitations(): Promise<number>;

  
  
  

  


  logAuditEvent(event: Omit<AuditEvent, 'id'>): Promise<AuditEvent>;

  


  getAuditEvents(filters: AuditEventFilters): Promise<AuditEvent[]>;

  


  getRecentAuditEvents(limit?: number): Promise<AuditEvent[]>;

  
  
  

  


  init(): Promise<void>;

  


  close(): Promise<void>;
}

export interface AtomicFirstUserBootstrapStorage extends Pick<
  IStorageAdapter,
  | 'claimFirstUserBootstrap'
  | 'finalizeFirstUserBootstrap'
  | 'getFirstUserBootstrapReceipt'
  | 'createUser'
> {}

export interface AdminIdentityStorage extends Pick<
  IStorageAdapter,
  | 'getUser'
  | 'getUserByHandle'
  | 'getUserByEmail'
  | 'getAllUsers'
  | 'createUser'
  | 'updateUser'
  | 'deleteUser'
  | 'hasUsers'
> {}

export interface BootstrapStorage extends Pick<
  IStorageAdapter,
  | 'claimFirstUserBootstrap'
  | 'finalizeFirstUserBootstrap'
  | 'getFirstUserBootstrapReceipt'
  | 'hasUsers'
  | 'getUser'
  | 'getTOTPSecret'
  | 'getBackupCodes'
  | 'logAuditEvent'
> {}

export interface HandleValidationStorage extends Pick<
  IStorageAdapter,
  | 'getUserByHandle'
  | 'getAllUsers'
  | 'createUser'
  | 'deleteUser'
> {}

export interface SessionStorage extends Pick<
  IStorageAdapter,
  | 'getSession'
  | 'getSessionsByUser'
  | 'getAllSessions'
  | 'createSession'
  | 'updateSession'
  | 'deleteSession'
  | 'deleteUserSessions'
  | 'cleanupExpiredSessions'
> {}

export interface ActivityTrackingStorage extends Pick<
  IStorageAdapter,
  | 'getSession'
  | 'updateSession'
> {}

export interface InvitationStorage extends Pick<
  IStorageAdapter,
  | 'getInvitation'
  | 'getInvitationById'
  | 'getAllInvitations'
  | 'getPendingInvitations'
  | 'createInvitation'
  | 'updateInvitation'
  | 'deleteInvitation'
  | 'cleanupExpiredInvitations'
> {}

export interface AuditStorage extends Pick<
  IStorageAdapter,
  | 'logAuditEvent'
  | 'getAuditEvents'
  | 'getRecentAuditEvents'
> {}




export interface AuditEventFilters {
  type?: string;
  userId?: string;
  startDate?: Date;
  endDate?: Date;
  severity?: string;
  limit?: number;
  offset?: number;
}




export interface StorageAdapterConfig {
  
  basePath?: string;
  
  connectionString?: string;
  
  options?: Record<string, unknown>;
}
