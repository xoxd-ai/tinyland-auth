






import { describe, it, expect } from 'vitest';
import {
  requireAuth,
  requireRole,
  adminGuard,
  checkAuth,
  protectEndpoint,
  getSessionFromLocals,
  getUserFromLocals,
  canManageTargetRole,
} from '../src/adapters/sveltekit/guards.js';
import type { Session, AdminUser, AdminRole } from '../src/types/auth.js';





function createMockSession(overrides: Partial<Session> = {}): Session {
  return {
    id: 'session-123',
    userId: 'user-456',
    expires: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    createdAt: new Date().toISOString(),
    clientIp: '127.0.0.1',
    userAgent: 'test-agent',
    user: {
      id: 'user-456',
      username: 'testuser',
      name: 'Test User',
      role: 'admin',
    },
    ...overrides,
  };
}

function createMockUser(overrides: Partial<AdminUser> = {}): AdminUser {
  return {
    id: 'user-456',
    handle: 'testuser',
    email: 'test@example.com',
    passwordHash: '$2b$12$hash',
    totpEnabled: false,
    role: 'admin' as AdminRole,
    isActive: true,
    needsOnboarding: false,
    onboardingStep: 0,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  };
}

function createMockLocals(options: {
  session?: Session | null;
  user?: AdminUser | null;
} = {}): App.Locals {
  return {
    session: options.session ?? null,
    user: options.user ?? null,
  } as unknown as App.Locals;
}

function createMockRequestEvent(options: {
  session?: Session | null;
  user?: AdminUser | null;
} = {}): any {
  return {
    locals: createMockLocals(options),
    request: new Request('http://localhost/api/test'),
    url: new URL('http://localhost/api/test'),
  };
}









function isRedirect(err: unknown): err is { status: number; location: string } {
  return (
    typeof err === 'object' &&
    err !== null &&
    'status' in err &&
    'location' in err
  );
}

function isHttpError(err: unknown): err is { status: number; body: { message: string } } {
  return (
    typeof err === 'object' &&
    err !== null &&
    'status' in err &&
    'body' in err
  );
}





describe('getSessionFromLocals', () => {
  it('should return session when present', () => {
    const session = createMockSession();
    const locals = createMockLocals({ session });

    expect(getSessionFromLocals(locals)).toBe(session);
  });

  it('should return null when no session', () => {
    const locals = createMockLocals({ session: null });
    expect(getSessionFromLocals(locals)).toBeNull();
  });
});

describe('getUserFromLocals', () => {
  it('should return user when present', () => {
    const user = createMockUser();
    const locals = createMockLocals({ user });

    expect(getUserFromLocals(locals)).toBe(user);
  });

  it('should return null when no user', () => {
    const locals = createMockLocals({ user: null });
    expect(getUserFromLocals(locals)).toBeNull();
  });
});

describe('requireAuth', () => {
  it('should return session and user when authenticated', () => {
    const session = createMockSession();
    const user = createMockUser();
    const locals = createMockLocals({ session, user });

    const result = requireAuth(locals);
    expect(result.session).toBe(session);
    expect(result.user).toBe(user);
  });

  it('should throw redirect when not authenticated', () => {
    const locals = createMockLocals({ session: null });

    try {
      requireAuth(locals);
      expect.fail('Should have thrown redirect');
    } catch (err) {
      expect(isRedirect(err)).toBe(true);
      if (isRedirect(err)) {
        expect(err.status).toBe(303);
        expect(err.location).toBe('/admin/login');
      }
    }
  });

  it('should redirect to custom login URL', () => {
    const locals = createMockLocals({ session: null });

    try {
      requireAuth(locals, { loginUrl: '/auth/signin' });
      expect.fail('Should have thrown redirect');
    } catch (err) {
      if (isRedirect(err)) {
        expect(err.location).toBe('/auth/signin');
      }
    }
  });

  it('should include return URL in redirect', () => {
    const locals = createMockLocals({ session: null });

    try {
      requireAuth(locals, { returnUrl: '/admin/dashboard' });
      expect.fail('Should have thrown redirect');
    } catch (err) {
      if (isRedirect(err)) {
        expect(err.location).toContain('returnUrl=');
        expect(err.location).toContain(encodeURIComponent('/admin/dashboard'));
      }
    }
  });

  it('should return undefined user when session exists but no user in locals', () => {
    const session = createMockSession();
    const locals = createMockLocals({ session, user: null });

    const result = requireAuth(locals);
    expect(result.session).toBe(session);
    expect(result.user).toBeUndefined();
  });
});

describe('requireRole', () => {
  it('should pass when user has sufficient role', () => {
    const session = createMockSession({
      user: { id: 'user-456', username: 'admin', name: 'Admin', role: 'admin' },
    });
    const user = createMockUser({ role: 'admin' });
    const locals = createMockLocals({ session, user });

    const result = requireRole(locals, 'editor');
    expect(result.session).toBe(session);
  });

  it('should pass when user has exact role', () => {
    const session = createMockSession({
      user: { id: 'user-456', username: 'editor', name: 'Editor', role: 'editor' },
    });
    const user = createMockUser({ role: 'editor' });
    const locals = createMockLocals({ session, user });

    const result = requireRole(locals, 'editor');
    expect(result.session).toBe(session);
  });

  it('should throw error when user has insufficient role', () => {
    const session = createMockSession({
      user: { id: 'user-456', username: 'viewer', name: 'Viewer', role: 'viewer' },
    });
    const user = createMockUser({ role: 'viewer' });
    const locals = createMockLocals({ session, user });

    try {
      requireRole(locals, 'admin');
      expect.fail('Should have thrown error');
    } catch (err) {
      if (isHttpError(err)) {
        expect(err.status).toBe(403);
      }
    }
  });

  it('should throw redirect when not authenticated at all', () => {
    const locals = createMockLocals({ session: null });

    try {
      requireRole(locals, 'admin');
      expect.fail('Should have thrown redirect');
    } catch (err) {
      expect(isRedirect(err)).toBe(true);
    }
  });

  it('should use custom error message', () => {
    const session = createMockSession({
      user: { id: 'user-456', username: 'viewer', name: 'Viewer', role: 'viewer' },
    });
    const locals = createMockLocals({ session });

    try {
      requireRole(locals, 'admin', { errorMessage: 'Admin access required' });
      expect.fail('Should have thrown error');
    } catch (err) {
      if (isHttpError(err)) {
        expect(err.body.message).toBe('Admin access required');
      }
    }
  });

  it('should allow super_admin for any role requirement', () => {
    const session = createMockSession({
      user: { id: 'user-456', username: 'superadmin', name: 'SA', role: 'super_admin' },
    });
    const user = createMockUser({ role: 'super_admin' });
    const locals = createMockLocals({ session, user });

    
    expect(() => requireRole(locals, 'admin')).not.toThrow();
    expect(() => requireRole(locals, 'moderator')).not.toThrow();
    expect(() => requireRole(locals, 'viewer')).not.toThrow();
  });

  it('rejects an embedded super_admin claim without an authoritative user', () => {
    const session = createMockSession({
      userId: 'pre-bootstrap-session-user',
      user: {
        id: 'pre-bootstrap-session-user',
        username: 'prebootstrap',
        name: 'Pre-bootstrap Session',
        role: 'super_admin',
      },
    });
    const locals = createMockLocals({ session, user: null });

    try {
      requireRole(locals, 'admin');
      expect.fail('Embedded pre-bootstrap role claim should not authorize');
    } catch (err) {
      expect(isHttpError(err)).toBe(true);
      if (isHttpError(err)) expect(err.status).toBe(403);
    }
  });
});

describe('adminGuard', () => {
  it('should pass when authenticated', () => {
    const session = createMockSession();
    const user = createMockUser();
    const locals = createMockLocals({ session, user });

    const result = adminGuard(locals);
    expect(result.session).toBe(session);
  });

  it('should redirect to /admin/login when not authenticated', () => {
    const locals = createMockLocals({ session: null });

    try {
      adminGuard(locals);
      expect.fail('Should have thrown redirect');
    } catch (err) {
      if (isRedirect(err)) {
        expect(err.location).toBe('/admin/login');
      }
    }
  });

  it('should use custom login URL override', () => {
    const locals = createMockLocals({ session: null });

    try {
      adminGuard(locals, { loginUrl: '/custom/login' });
      expect.fail('Should have thrown redirect');
    } catch (err) {
      if (isRedirect(err)) {
        expect(err.location).toBe('/custom/login');
      }
    }
  });
});

describe('checkAuth', () => {
  it('should return allowed:true when authenticated', async () => {
    const session = createMockSession();
    const user = createMockUser();
    const locals = createMockLocals({ session, user });

    const result = await checkAuth(locals);
    expect(result.allowed).toBe(true);
    expect(result.session).toBe(session);
    expect(result.user).toBe(user);
  });

  it('should return allowed:false when not authenticated', async () => {
    const locals = createMockLocals({ session: null });

    const result = await checkAuth(locals);
    expect(result.allowed).toBe(false);
    expect(result.redirectUrl).toBe('/admin/login');
    expect(result.error).toBe('Authentication required');
  });

  it('should check role requirement', async () => {
    const session = createMockSession({
      user: { id: 'user-456', username: 'viewer', name: 'Viewer', role: 'viewer' },
    });
    const locals = createMockLocals({ session });

    const result = await checkAuth(locals, { requiredRole: 'admin' });
    expect(result.allowed).toBe(false);
    expect(result.error).toContain('admin');
  });

  it('should pass role check with sufficient role', async () => {
    const session = createMockSession({
      user: { id: 'user-456', username: 'admin', name: 'Admin', role: 'admin' },
    });
    const user = createMockUser({ role: 'admin' });
    const locals = createMockLocals({ session, user });

    const result = await checkAuth(locals, { requiredRole: 'editor' });
    expect(result.allowed).toBe(true);
  });

  it('uses the loaded user role instead of a conflicting embedded role', async () => {
    const session = createMockSession({
      user: {
        id: 'user-456',
        username: 'forged-admin',
        name: 'Forged Admin',
        role: 'super_admin',
      },
    });
    const user = createMockUser({ role: 'viewer' });
    const locals = createMockLocals({ session, user });

    await expect(checkAuth(locals, { requiredRole: 'admin' })).resolves.toMatchObject({
      allowed: false,
      error: expect.stringMatching(/admin/),
    });
  });

  it('should use custom login URL', async () => {
    const locals = createMockLocals({ session: null });

    const result = await checkAuth(locals, { loginUrl: '/signin' });
    expect(result.redirectUrl).toBe('/signin');
  });
});

describe('protectEndpoint', () => {
  it('should return session when authenticated', () => {
    const session = createMockSession();
    const user = createMockUser();
    const event = createMockRequestEvent({ session, user });

    const result = protectEndpoint(event);
    expect(result.session).toBe(session);
    expect(result.user).toBe(user);
  });

  it('should throw 401 when not authenticated', () => {
    const event = createMockRequestEvent({ session: null });

    try {
      protectEndpoint(event);
      expect.fail('Should have thrown error');
    } catch (err) {
      if (isHttpError(err)) {
        expect(err.status).toBe(401);
      }
    }
  });

  it('should throw 403 when role is insufficient', () => {
    const session = createMockSession({
      user: { id: 'user-456', username: 'viewer', name: 'Viewer', role: 'viewer' },
    });
    const event = createMockRequestEvent({ session });

    try {
      protectEndpoint(event, { requiredRole: 'admin' });
      expect.fail('Should have thrown error');
    } catch (err) {
      if (isHttpError(err)) {
        expect(err.status).toBe(403);
      }
    }
  });

  it('should pass with sufficient role', () => {
    const session = createMockSession({
      user: { id: 'user-456', username: 'admin', name: 'Admin', role: 'super_admin' },
    });
    const user = createMockUser({ role: 'super_admin' });
    const event = createMockRequestEvent({ session, user });

    const result = protectEndpoint(event, { requiredRole: 'admin' });
    expect(result.session).toBe(session);
  });
});

describe('canManageTargetRole', () => {
  it('should return true when current user can manage target role', () => {
    const session = createMockSession({
      user: { id: 'user-456', username: 'admin', name: 'Admin', role: 'super_admin' },
    });
    const user = createMockUser({ role: 'super_admin' });
    const locals = createMockLocals({ session, user });

    expect(canManageTargetRole(locals, 'admin')).toBe(true);
    expect(canManageTargetRole(locals, 'viewer')).toBe(true);
  });

  it('should return false when current user cannot manage target role', () => {
    const session = createMockSession({
      user: { id: 'user-456', username: 'viewer', name: 'Viewer', role: 'viewer' },
    });
    const user = createMockUser({ role: 'viewer' });
    const locals = createMockLocals({ session, user });

    expect(canManageTargetRole(locals, 'admin')).toBe(false);
    expect(canManageTargetRole(locals, 'viewer')).toBe(false);
  });

  it('should return false when no session', () => {
    const locals = createMockLocals({ session: null });
    expect(canManageTargetRole(locals, 'viewer')).toBe(false);
  });
});

describe('Guard Role Hierarchy', () => {
  const roles: AdminRole[] = [
    'super_admin',
    'admin',
    'moderator',
    'editor',
    'event_manager',
    'contributor',
    'member',
    'viewer',
  ];

  it('INVARIANT: higher roles always pass guards for lower role requirements', () => {
    for (let i = 0; i < roles.length; i++) {
      for (let j = i; j < roles.length; j++) {
        const currentRole = roles[i]; 
        const requiredRole = roles[j]; 

        const session = createMockSession({
          user: {
            id: 'user-456',
            username: currentRole,
            name: currentRole,
            role: currentRole,
          },
        });
        const user = createMockUser({ role: currentRole });
        const locals = createMockLocals({ session, user });

        
        expect(() => requireRole(locals, requiredRole)).not.toThrow();
      }
    }
  });

  it('INVARIANT: lower roles always fail guards for higher role requirements', () => {
    for (let i = 1; i < roles.length; i++) {
      const currentRole = roles[i]; 
      const requiredRole = roles[0]; 

      const session = createMockSession({
        user: {
          id: 'user-456',
          username: currentRole,
          name: currentRole,
          role: currentRole,
        },
      });
      const locals = createMockLocals({ session });

      try {
        requireRole(locals, requiredRole);
        expect.fail(`${currentRole} should not pass ${requiredRole} guard`);
      } catch (err) {
        if (isHttpError(err)) {
          expect(err.status).toBe(403);
        }
      }
    }
  });
});
