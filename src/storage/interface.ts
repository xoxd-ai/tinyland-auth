








import type {
  AdminUser,
  Session,
  SessionMetadata,
  EncryptedTOTPSecret,
  BackupCodeSet,
  AdminInvitation,
  AuditEvent,
} from '../types/auth.js';
import type { BoundedSessionPolicy } from '../types/config.js';






export interface IStorageAdapter {
  
  
  

  


  getUser(id: string): Promise<AdminUser | null>;

  


  getUserByHandle(handle: string): Promise<AdminUser | null>;

  


  getUserByEmail(email: string): Promise<AdminUser | null>;

  


  getAllUsers(): Promise<AdminUser[]>;

  


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

  /** Atomic bounded insertion; unsupported adapters must not emulate this with separate writes. */
  createSessionWithPolicy?(
    userId: string,
    user: Partial<AdminUser>,
    metadata: SessionMetadata | undefined,
    policy: BoundedSessionPolicy,
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
  | 'hasUsers'
  | 'createUser'
  | 'getTOTPSecret'
  | 'saveTOTPSecret'
  | 'saveBackupCodes'
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
  | 'createSessionWithPolicy'
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
