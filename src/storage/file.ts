








import { promises as fs } from 'fs';
import path from 'path';
import { randomBytes, randomUUID } from 'crypto';
import type { BoundedSessionPolicy } from '../types/config.js';
import { assertBoundedSessionPolicy, assertStoredSessions, boundedSessions } from './session-policy.js';
import type { IStorageAdapter, StorageAdapterConfig, AuditEventFilters } from './interface.js';
import type {
  AdminUser,
  Session,
  SessionMetadata,
  AdminInvitation,
  BackupCodeSet,
  AuditEvent,
  EncryptedTOTPSecret,
} from '../types/index.js';

export interface FileStorageConfig extends StorageAdapterConfig {
  
  authDir: string;
  
  totpDir: string;
  
  sessionMaxAge: number;
}

const DEFAULT_CONFIG: FileStorageConfig = {
  authDir: 'content/auth',
  totpDir: '.totp-secrets',
  sessionMaxAge: 7 * 24 * 60 * 60 * 1000, 
};

// One process owns this storage root. Sharing the queue across adapter instances
// prevents lost updates; it does not claim cross-process/distributed locking.
const sessionFileTails = new Map<string, Promise<unknown>>();

function withSessionFileQueue<T>(filename: string, operation: () => Promise<T>): Promise<T> {
  const key = path.resolve(filename);
  const previous = sessionFileTails.get(key) ?? Promise.resolve();
  const current = previous.then(operation, operation);
  sessionFileTails.set(key, current);
  const cleanup = () => {
    if (sessionFileTails.get(key) === current) sessionFileTails.delete(key);
  };
  void current.then(cleanup, cleanup);
  return current;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isText(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && !value.includes('\0');
}

function isTimestamp(value: unknown): value is string {
  return isText(value) && Number.isFinite(Date.parse(value));
}

function isStoredFactor(value: unknown, handle: string): value is EncryptedTOTPSecret {
  if (!isRecord(value)) return false;
  return value.handle === handle && isText(value.userId)
    && ['encryptedSecret', 'iv', 'authTag', 'salt'].every(key => isText(value[key]))
    && isTimestamp(value.createdAt)
    && (value.lastUsedAt === undefined || isTimestamp(value.lastUsedAt))
    && (value.lastUsedTotpStep === undefined || (Number.isSafeInteger(value.lastUsedTotpStep) && (value.lastUsedTotpStep as number) >= 0))
    && typeof value.backupCodesGenerated === 'boolean'
    && Number.isSafeInteger(value.version) && (value.version as number) >= 1;
}

function isStoredBackupCodes(value: unknown, userId: string): value is BackupCodeSet {
  if (!isRecord(value) || value.userId !== userId || !Array.isArray(value.codes)
    || !isTimestamp(value.generatedAt)
    || (value.lastUsedAt !== undefined && !isTimestamp(value.lastUsedAt))) return false;
  const ids = new Set<string>();
  const hashes = new Set<string>();
  return value.codes.every(code => {
    if (!isRecord(code) || !isText(code.id) || typeof code.hash !== 'string'
      || !/^[a-f0-9]{64}$/.test(code.hash) || typeof code.used !== 'boolean'
      || (code.usedAt !== undefined && !isTimestamp(code.usedAt))
      || ids.has(code.id) || hashes.has(code.hash)) return false;
    ids.add(code.id);
    hashes.add(code.hash);
    return true;
  });
}
















export class FileStorageAdapter implements IStorageAdapter {
  private config: FileStorageConfig;
  private basePath: string;
  
  private locks = new Map<string, Promise<void>>();

  constructor(config: Partial<FileStorageConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.basePath = process.cwd();
  }

  
  
  

  async init(): Promise<void> {
    
    await this.ensureDir(this.getPath('admin-users.json'));
    await this.ensureDir(this.getPath('sessions.json'));
    await this.ensureDir(this.getPath('invites.json'));
    await this.ensureDir(this.getPath('logs/audit.json'));
    await this.ensureDir(path.join(this.basePath, this.config.totpDir, 'backup-codes', '.gitkeep'));
  }

  async close(): Promise<void> {
    
  }

  async hasUsers(): Promise<boolean> {
    const users = await this.readJsonFile<AdminUser[]>(this.getPath('admin-users.json'), []);
    return users.length > 0;
  }

  async getAllSessions(): Promise<Session[]> {
    return withSessionFileQueue(this.getPath('sessions.json'), () => this.readSessions());
  }

  private async readSessions(): Promise<Session[]> {
    const sessions = await this.readJsonFile<unknown>(this.getPath('sessions.json'), []);
    assertStoredSessions(sessions);
    return sessions;
  }

  private mutateSessions<T>(
    operation: (sessions: Session[]) => { sessions: Session[]; result: T },
  ): Promise<T> {
    const filename = this.getPath('sessions.json');
    return withSessionFileQueue(filename, async () => {
      const next = operation(await this.readSessions());
      assertStoredSessions(next.sessions);
      // Already inside the full read/modify/write queue: do not re-enter it.
      await this.writeJsonFileAtomic(filename, next.sessions);
      return next.result;
    });
  }

  
  
  

  private getPath(filename: string): string {
    return path.join(this.basePath, this.config.authDir, filename);
  }

  private getTotpPath(handle: string): string {
    return path.join(this.basePath, this.config.totpDir, `${handle}.json`);
  }

  private getBackupCodesPath(userId: string): string {
    return path.join(this.basePath, this.config.totpDir, 'backup-codes', `${userId}.json`);
  }

  private async ensureDir(filePath: string): Promise<void> {
    const dir = path.dirname(filePath);
    try {
      await fs.access(dir);
    } catch {
      await fs.mkdir(dir, { recursive: true });
    }
  }

  private async readJsonFile<T>(filePath: string, defaultValue: T): Promise<T> {
    try {
      await this.ensureDir(filePath);
      const content = await fs.readFile(filePath, 'utf8');
      return JSON.parse(content) as T;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return defaultValue;
      }
      throw error;
    }
  }

  



  private async writeJsonFile<T>(filePath: string, data: T): Promise<void> {
    await this.withFileLock(filePath, async () => {
      await this.writeJsonFileAtomic(filePath, data);
    });
  }

  



  private async writeJsonFileAtomic<T>(filePath: string, data: T): Promise<void> {
    await this.ensureDir(filePath);
    const tempPath = `${filePath}.${Date.now()}.${randomBytes(4).toString('hex')}.tmp`;

    try {
      const temporary = await fs.open(tempPath, 'wx', 0o600);
      try {
        await temporary.writeFile(JSON.stringify(data, null, 2), 'utf8');
        await temporary.sync();
      } finally {
        await temporary.close();
      }
      await fs.rename(tempPath, filePath);
      const directory = await fs.open(path.dirname(filePath), 'r');
      try {
        await directory.sync();
      } finally {
        await directory.close();
      }
    } catch (error) {
      
      try { await fs.unlink(tempPath); } catch {  }
      throw error;
    }
  }

  



  private async withFileLock<T>(filePath: string, operation: () => Promise<T>): Promise<T> {
    
    const existing = this.locks.get(filePath);
    if (existing) {
      await existing;
    }

    
    let resolve: () => void;
    const lockPromise = new Promise<void>(r => { resolve = r; });
    this.locks.set(filePath, lockPromise);

    try {
      return await operation();
    } finally {
      resolve!();
      this.locks.delete(filePath);
    }
  }

  
  
  

  async getUser(id: string): Promise<AdminUser | null> {
    const users = await this.readJsonFile<AdminUser[]>(this.getPath('admin-users.json'), []);
    return users.find(u => u.id === id) || null;
  }

  async getUserByHandle(handle: string): Promise<AdminUser | null> {
    const users = await this.readJsonFile<AdminUser[]>(this.getPath('admin-users.json'), []);
    return users.find(u => u.handle === handle) || null;
  }

  async getUserByEmail(email: string): Promise<AdminUser | null> {
    const users = await this.readJsonFile<AdminUser[]>(this.getPath('admin-users.json'), []);
    return users.find(u => u.email === email) || null;
  }

  async createUser(userData: Omit<AdminUser, 'id'>): Promise<AdminUser> {
    const users = await this.readJsonFile<AdminUser[]>(this.getPath('admin-users.json'), []);

    const user: AdminUser = {
      id: randomUUID(),
      ...userData,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    users.push(user);
    await this.writeJsonFile(this.getPath('admin-users.json'), users);
    return user;
  }

  async updateUser(id: string, updates: Partial<AdminUser>): Promise<AdminUser> {
    const users = await this.readJsonFile<AdminUser[]>(this.getPath('admin-users.json'), []);
    const index = users.findIndex(u => u.id === id);

    if (index === -1) {
      throw new Error(`User not found: ${id}`);
    }

    users[index] = {
      ...users[index],
      ...updates,
      updatedAt: new Date().toISOString(),
    };

    await this.writeJsonFile(this.getPath('admin-users.json'), users);
    return users[index];
  }

  async deleteUser(id: string): Promise<boolean> {
    const users = await this.readJsonFile<AdminUser[]>(this.getPath('admin-users.json'), []);
    const index = users.findIndex(u => u.id === id);

    if (index === -1) return false;

    users.splice(index, 1);
    await this.writeJsonFile(this.getPath('admin-users.json'), users);
    return true;
  }

  async getAllUsers(): Promise<AdminUser[]> {
    return this.readJsonFile<AdminUser[]>(this.getPath('admin-users.json'), []);
  }

  
  
  

  async getSession(id: string): Promise<Session | null> {
    const sessions = await this.getAllSessions();
    return sessions.find(s => s.id === id) || null;
  }

  async createSession(
    userId: string,
    userData: Partial<AdminUser>,
    metadata?: SessionMetadata
  ): Promise<Session> {
    return this.insertSession(userId, userData, metadata);
  }

  async createSessionWithPolicy(
    userId: string,
    userData: Partial<AdminUser>,
    metadata: SessionMetadata | undefined,
    policy: BoundedSessionPolicy,
  ): Promise<Session> {
    assertBoundedSessionPolicy(policy);
    return this.insertSession(userId, userData, metadata, { ...policy });
  }

  private insertSession(
    userId: string,
    userData: Partial<AdminUser>,
    metadata?: SessionMetadata,
    policy?: BoundedSessionPolicy,
  ): Promise<Session> {
    return this.mutateSessions((sessions) => {
      const now = new Date();
      const expires = new Date(now.getTime() + this.config.sessionMaxAge);
      const session: Session = {
        id: randomBytes(32).toString('hex'),
        userId,
        expires: expires.toISOString(),
        expiresAt: expires.toISOString(),
        createdAt: now.toISOString(),
        user: userData.id ? {
          id: userData.id,
          username: userData.handle || '',
          name: userData.displayName || userData.handle || '',
          role: userData.role || 'viewer',
          needsOnboarding: userData.needsOnboarding,
          onboardingStep: userData.onboardingStep,
        } : undefined,
        clientIp: metadata?.clientIp || '',
        clientIpMasked: metadata?.clientIpMasked,
        userAgent: metadata?.userAgent || '',
        deviceType: metadata?.deviceType,
        browserFingerprint: metadata?.browserFingerprint,
        geoLocation: metadata?.geoLocation,
      };

      return {
        sessions: policy ? boundedSessions(sessions, session, policy, now.getTime()) : [...sessions, session],
        result: session,
      };
    });
  }

  async updateSession(id: string, updates: Partial<Session>): Promise<Session> {
    return this.mutateSessions((sessions) => {
      const index = sessions.findIndex(s => s.id === id);
      if (index === -1) throw new Error(`Session not found: ${id}`);
      sessions[index] = { ...sessions[index], ...updates };
      return { sessions, result: sessions[index] };
    });
  }

  async deleteSession(id: string): Promise<boolean> {
    return this.mutateSessions((sessions) => {
      const index = sessions.findIndex(s => s.id === id);
      if (index === -1) return { sessions, result: false };
      sessions.splice(index, 1);
      return { sessions, result: true };
    });
  }

  async deleteUserSessions(userId: string): Promise<number> {
    return this.mutateSessions((sessions) => {
      const before = sessions.length;
      const filtered = sessions.filter(s => s.userId !== userId);
      return { sessions: filtered, result: before - filtered.length };
    });
  }

  async getSessionsByUser(userId: string): Promise<Session[]> {
    const sessions = await this.getAllSessions();
    return sessions.filter(s => s.userId === userId);
  }

  async cleanupExpiredSessions(): Promise<number> {
    return this.mutateSessions((sessions) => {
      const now = new Date();
      const before = sessions.length;
      const filtered = sessions.filter(s => new Date(s.expires) > now);
      return { sessions: filtered, result: before - filtered.length };
    });
  }

  
  
  

  async getTOTPSecret(handle: string): Promise<EncryptedTOTPSecret | null> {
    // Only a missing file is absence. Parse, permissions and shape failures
    // must never authorize enrollment to replace an existing credential.
    const secret = await this.readJsonFile<unknown>(this.getTotpPath(handle), undefined);
    if (secret === undefined) return null;
    if (!isStoredFactor(secret, handle)) throw new Error('Invalid stored TOTP credential');
    return secret;
  }

  async saveTOTPSecret(handle: string, secret: EncryptedTOTPSecret): Promise<void> {
    await this.writeJsonFile(this.getTotpPath(handle), secret);
  }

  async deleteTOTPSecret(handle: string): Promise<boolean> {
    try {
      await fs.unlink(this.getTotpPath(handle));
      return true;
    } catch {
      return false;
    }
  }

  
  
  

  async getBackupCodes(userId: string): Promise<BackupCodeSet | null> {
    const codes = await this.readJsonFile<unknown>(this.getBackupCodesPath(userId), undefined);
    if (codes === undefined) return null;
    if (!isStoredBackupCodes(codes, userId)) throw new Error('Invalid stored backup-code credential');
    return codes;
  }

  async saveBackupCodes(userId: string, codeSet: BackupCodeSet): Promise<void> {
    await this.writeJsonFile(this.getBackupCodesPath(userId), codeSet);
  }

  async deleteBackupCodes(userId: string): Promise<boolean> {
    try {
      await fs.unlink(this.getBackupCodesPath(userId));
      return true;
    } catch {
      return false;
    }
  }

  
  
  

  async getInvitation(token: string): Promise<AdminInvitation | null> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    return invites.find(i => i.token === token) || null;
  }

  async getInvitationById(id: string): Promise<AdminInvitation | null> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    return invites.find(i => i.id === id) || null;
  }

  async createInvitation(data: Omit<AdminInvitation, 'id'>): Promise<AdminInvitation> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);

    const invitation: AdminInvitation = {
      id: randomUUID(),
      ...data,
    };

    invites.push(invitation);
    await this.writeJsonFile(this.getPath('invites.json'), invites);
    return invitation;
  }

  async updateInvitation(token: string, updates: Partial<AdminInvitation>): Promise<AdminInvitation> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    const index = invites.findIndex(i => i.token === token);

    if (index === -1) {
      throw new Error(`Invitation not found: ${token}`);
    }

    invites[index] = { ...invites[index], ...updates };
    await this.writeJsonFile(this.getPath('invites.json'), invites);
    return invites[index];
  }

  async deleteInvitation(token: string): Promise<boolean> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    const index = invites.findIndex(i => i.token === token);

    if (index === -1) return false;

    invites.splice(index, 1);
    await this.writeJsonFile(this.getPath('invites.json'), invites);
    return true;
  }

  async getPendingInvitations(): Promise<AdminInvitation[]> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    const now = new Date();
    return invites.filter(i => new Date(i.expiresAt) > now && !i.usedAt && i.isActive);
  }

  async getAllInvitations(): Promise<AdminInvitation[]> {
    return this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
  }

  async cleanupExpiredInvitations(): Promise<number> {
    const invites = await this.readJsonFile<AdminInvitation[]>(this.getPath('invites.json'), []);
    const now = new Date();
    const before = invites.length;
    const filtered = invites.filter(i =>
      new Date(i.expiresAt) > now || i.usedAt
    );
    await this.writeJsonFile(this.getPath('invites.json'), filtered);
    return before - filtered.length;
  }

  
  
  

  async logAuditEvent(event: Omit<AuditEvent, 'id'>): Promise<AuditEvent> {
    const logPath = this.getPath('logs/audit.json');
    const events = await this.readJsonFile<AuditEvent[]>(logPath, []);

    const auditEvent: AuditEvent = {
      id: randomUUID(),
      ...event,
    };

    events.push(auditEvent);

    
    if (events.length > 10000) {
      events.splice(0, events.length - 10000);
    }

    await this.writeJsonFile(logPath, events);
    return auditEvent;
  }

  async getAuditEvents(filters: AuditEventFilters): Promise<AuditEvent[]> {
    const logPath = this.getPath('logs/audit.json');
    let events = await this.readJsonFile<AuditEvent[]>(logPath, []);

    if (filters.type) {
      events = events.filter(e => e.type === filters.type);
    }

    if (filters.userId) {
      events = events.filter(e => e.userId === filters.userId || e.targetUserId === filters.userId);
    }

    if (filters.severity) {
      events = events.filter(e => e.severity === filters.severity);
    }

    if (filters.startDate) {
      const start = filters.startDate.getTime();
      events = events.filter(e => new Date(e.timestamp).getTime() >= start);
    }

    if (filters.endDate) {
      const end = filters.endDate.getTime();
      events = events.filter(e => new Date(e.timestamp).getTime() <= end);
    }

    const limit = filters.limit || 100;
    const offset = filters.offset || 0;

    return events.slice(offset, offset + limit);
  }

  async getRecentAuditEvents(limit: number = 100): Promise<AuditEvent[]> {
    const logPath = this.getPath('logs/audit.json');
    const events = await this.readJsonFile<AuditEvent[]>(logPath, []);
    return events.slice(-limit).reverse();
  }
}




export function createFileStorageAdapter(config?: Partial<FileStorageConfig>): FileStorageAdapter {
  return new FileStorageAdapter(config);
}
