





export interface AuthConfig {
  
  appName: string;
  
  appUrl: string;
  
  isDevelopment: boolean;

  
  totp: TOTPConfig;
  
  session: SessionConfig;
  
  password: PasswordConfig;
  
  rateLimit: RateLimitConfig;
  
  invitation: InvitationConfig;
  
  backupCodes: BackupCodesConfig;
  
  security: SecurityConfig;
}

export interface TOTPConfig {
  
  enabled: boolean;
  
  issuer: string;
  
  encryptionKey: string;
  
  devMode: boolean;
  
  digits: number;
  
  period: number;
  
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  
  window: number;
  
  secretLength: number;
  
  backupCodesCount: number;
}

export interface BoundedSessionPolicy {
  maxConcurrentSessions: number;
  overflow: 'evict-oldest-created';
}

export interface SessionConfig {
  /** Existing consumers remain single-session until explicitly opted in. */
  sessionStrategy?: 'single' | 'bounded';
  
  maxAge: number;
  
  cookieName: string;
  
  secureCookie: boolean;
  
  sameSite: 'strict' | 'lax' | 'none';
  
  httpOnly: boolean;
  
  renewThreshold: number;
  
  maxConcurrentSessions: number;
  
  rememberMeDuration: number;
}

export interface PasswordConfig {
  
  minLength: number;
  
  requireUppercase: boolean;
  
  requireLowercase: boolean;
  
  requireNumbers: boolean;
  
  requireSpecialChars: boolean;
  
  bcryptRounds: number;
}

export interface RateLimitConfig {
  
  maxLoginAttempts: number;
  
  lockoutDuration: number;
  
  slidingWindow: number;
  
  maxInvitationsPerHour: number;
}

export interface InvitationConfig {
  
  defaultExpiryHours: number;
  
  maxActiveInvitations: number;
  
  allowEmailOverride: boolean;
}

export interface BackupCodesConfig {
  
  count: number;
  
  length: number;
  
  format: RegExp;
}

export interface SecurityConfig {
  
  auditLogging: boolean;
  
  sessionRotation: boolean;
  
  ipValidation: boolean;
  
  accountLockout: {
    enabled: boolean;
    threshold: number;
    duration: number;
  };
  
  reAuthRequired: {
    enabled: boolean;
    operations: string[];
    timeout: number;
  };
}




export const DEFAULT_AUTH_CONFIG: AuthConfig = {
  appName: 'Tinyland.dev',
  appUrl: 'http://localhost:9080',
  isDevelopment: process.env.NODE_ENV === 'development',

  totp: {
    enabled: true,
    issuer: 'Tinyland.dev',
    encryptionKey: '',
    devMode: false,
    digits: 6,
    period: 30,
    algorithm: 'SHA1',
    window: 1,
    secretLength: 32,
    backupCodesCount: 8,
  },

  session: {
    maxAge: 7 * 24 * 60 * 60 * 1000, 
    cookieName: 'sessionId',
    secureCookie: true,
    sameSite: 'lax',
    httpOnly: true,
    renewThreshold: 24 * 60 * 60 * 1000, 
    maxConcurrentSessions: 5,
    rememberMeDuration: 30 * 24 * 60 * 60 * 1000, 
  },

  password: {
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    bcryptRounds: 12,
  },

  rateLimit: {
    maxLoginAttempts: 5,
    lockoutDuration: 15 * 60 * 1000, 
    slidingWindow: 60 * 60 * 1000, 
    maxInvitationsPerHour: 10,
  },

  invitation: {
    defaultExpiryHours: 72,
    maxActiveInvitations: 50,
    allowEmailOverride: true,
  },

  backupCodes: {
    count: 10,
    length: 8,
    format: /^[A-Z0-9]{4}-[A-Z0-9]{4}$/,
  },

  security: {
    auditLogging: true,
    sessionRotation: true,
    ipValidation: false,
    accountLockout: {
      enabled: true,
      threshold: 5,
      duration: 30 * 60 * 1000, 
    },
    reAuthRequired: {
      enabled: true,
      operations: ['deleteUser', 'changeRole', 'resetTOTP'],
      timeout: 5 * 60 * 1000, 
    },
  },
};




export function createAuthConfig(overrides: Partial<AuthConfig> = {}): AuthConfig {
  return {
    ...DEFAULT_AUTH_CONFIG,
    ...overrides,
    totp: { ...DEFAULT_AUTH_CONFIG.totp, ...overrides.totp },
    session: { ...DEFAULT_AUTH_CONFIG.session, ...overrides.session },
    password: { ...DEFAULT_AUTH_CONFIG.password, ...overrides.password },
    rateLimit: { ...DEFAULT_AUTH_CONFIG.rateLimit, ...overrides.rateLimit },
    invitation: { ...DEFAULT_AUTH_CONFIG.invitation, ...overrides.invitation },
    backupCodes: { ...DEFAULT_AUTH_CONFIG.backupCodes, ...overrides.backupCodes },
    security: { ...DEFAULT_AUTH_CONFIG.security, ...overrides.security },
  };
}
