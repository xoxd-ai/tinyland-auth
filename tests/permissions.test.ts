





import { describe, it, expect } from 'vitest';
import {
  ADMIN_ROLES,
  ROLE_HIERARCHY,
  ROLE_MANAGEMENT_ORDER,
  hasEqualOrHigherRole,
  hasHigherRole,
  isValidAdminRole,
  type AdminRole,
  type AdminUser,
} from '../src/types/auth.js';
import {
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  getRolePermissions,
  getUserPermissions,
  requirePermission,
  requireAnyPermission,
  requireAllPermissions,
  isValidPermission,
  getPermissionDisplayName,
  canManageRole,
  canCreatePublicContent,
  canDeliverFederation,
  canViewContent,
  filterContentByVisibility,
  getAllowedVisibilityOptions,
  isMemberRole,
} from '../src/core/permissions/index.js';
import { EXPLICIT_USER_PERMISSIONS, PERMISSIONS, ROLE_PERMISSIONS } from '../src/types/permissions.js';


const createTestUser = (role: string, id = 'user-1'): AdminUser => ({
  id,
  handle: `test_${role}`,
  email: `${role}@test.com`,
  passwordHash: 'hash',
  totpEnabled: false,
  role: role as AdminUser['role'],
  isActive: true,
  needsOnboarding: false,
  onboardingStep: 0,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
});

const superAdmin = createTestUser('super_admin');
const admin = createTestUser('admin');
const moderator = createTestUser('moderator');
const editor = createTestUser('editor');
const eventManager = createTestUser('event_manager');
const contributor = createTestUser('contributor');
const member = createTestUser('member');
const viewer = createTestUser('viewer');

describe('Permission Functions', () => {
  describe('role authority', () => {
    const expectedManagementOrder: AdminRole[] = [
      'super_admin',
      'admin',
      'moderator',
      'editor',
      'event_manager',
      'contributor',
      'member',
      'viewer',
    ];

    it('exports the complete supported role set', () => {
      expect(ADMIN_ROLES).toEqual(expectedManagementOrder);
      for (const role of expectedManagementOrder) {
        expect(isValidAdminRole(role)).toBe(true);
      }
      expect(isValidAdminRole('owner')).toBe(false);
    });

    it('derives role-management order from ROLE_HIERARCHY', () => {
      expect(ROLE_MANAGEMENT_ORDER).toEqual(expectedManagementOrder);

      for (const [index, role] of ROLE_MANAGEMENT_ORDER.entries()) {
        const lowerRole = ROLE_MANAGEMENT_ORDER[index + 1];
        if (!lowerRole) continue;

        expect(ROLE_HIERARCHY[role]).toBeGreaterThan(
          ROLE_HIERARCHY[lowerRole],
        );
        expect(hasHigherRole(role, lowerRole)).toBe(true);
        expect(hasEqualOrHigherRole(role, lowerRole)).toBe(true);
      }
    });

    it('uses ROLE_HIERARCHY as the canManageRole authority', () => {
      for (const actorRole of ADMIN_ROLES) {
        for (const targetRole of ADMIN_ROLES) {
          expect(canManageRole(actorRole, targetRole)).toBe(
            ROLE_HIERARCHY[actorRole] > ROLE_HIERARCHY[targetRole],
          );
        }
      }

      expect(canManageRole('super-admin', 'event-manager')).toBe(true);
      expect(canManageRole('editor', 'moderator')).toBe(false);
      expect(canManageRole('moderator', 'editor')).toBe(true);
      expect(canManageRole('admin', 'owner')).toBe(false);
    });

    it('documents permissions as a capability lattice, not a strict superset hierarchy', () => {
      // TIN-1606 (ratified product policy): specialist capabilities do not
      // nest across the governance order. contributor never inherits event
      // management from the adjacent event_manager rank.
      expect(ROLE_PERMISSIONS.event_manager).toContain(
        PERMISSIONS.ADMIN_EVENTS_MANAGE,
      );
      expect(ROLE_PERMISSIONS.contributor).toContain(
        PERMISSIONS.ADMIN_CONTENT_VIEW,
      );
      expect(ROLE_PERMISSIONS.contributor).not.toContain(
        PERMISSIONS.ADMIN_EVENTS_MANAGE,
      );
      // TIN-2435 P2: event_manager ranks above member, so it now holds the
      // member self-service core, including admin.content.view. The
      // TIN-1606 principle stands via manage-level capabilities.
      expect(ROLE_PERMISSIONS.event_manager).toContain(
        PERMISSIONS.ADMIN_CONTENT_VIEW,
      );
    });
  });

  describe('hasPermission', () => {
    it('should return true for super_admin with administrative permissions', () => {
      expect(hasPermission(superAdmin, PERMISSIONS.ADMIN_ACCESS)).toBe(true);
      expect(hasPermission(superAdmin, PERMISSIONS.ADMIN_USERS_MANAGE)).toBe(true);
      expect(hasPermission(superAdmin, PERMISSIONS.ADMIN_SECURITY_MANAGE)).toBe(true);
    });

    it('should return true for admin with user management', () => {
      expect(hasPermission(admin, PERMISSIONS.ADMIN_USERS_VIEW)).toBe(true);
      expect(hasPermission(admin, PERMISSIONS.ADMIN_USERS_MANAGE)).toBe(true);
    });

    it('should return false for viewer with user management permissions', () => {
      expect(hasPermission(viewer, PERMISSIONS.ADMIN_USERS_MANAGE)).toBe(false);
      expect(hasPermission(viewer, PERMISSIONS.ADMIN_CONTENT_MANAGE)).toBe(false);
    });

    it('should return true for viewer with admin access', () => {
      expect(hasPermission(viewer, PERMISSIONS.ADMIN_ACCESS)).toBe(true);
      expect(hasPermission(viewer, PERMISSIONS.ADMIN_ANALYTICS_VIEW)).toBe(true);
    });

    it('should return true for editor with content permissions', () => {
      expect(hasPermission(editor, PERMISSIONS.ADMIN_CONTENT_VIEW)).toBe(true);
      expect(hasPermission(editor, PERMISSIONS.ADMIN_CONTENT_MANAGE)).toBe(true);
    });
  });

  describe('explicit own-scope permissions', () => {
    it('registers exact IDs and descriptive names', () => {
      expect(EXPLICIT_USER_PERMISSIONS).toEqual([
        'content.own.publish',
        'federation.own.deliver',
      ]);
      expect(Object.isFrozen(EXPLICIT_USER_PERMISSIONS)).toBe(true);
      for (const permission of EXPLICIT_USER_PERMISSIONS) {
        expect(isValidPermission(permission)).toBe(true);
      }
      expect(isValidPermission('content.own.manage')).toBe(false);
      expect(getPermissionDisplayName(PERMISSIONS.CONTENT_OWN_PUBLISH)).toBe('Publish Own Public Content');
      expect(getPermissionDisplayName(PERMISSIONS.FEDERATION_OWN_DELIVER)).toBe('Deliver Own Federation Content');
    });

    it.each(ADMIN_ROLES)('%s receives neither own-scope permission by default', role => {
      const user = createTestUser(role);
      for (const permission of EXPLICIT_USER_PERMISSIONS) {
        expect(getRolePermissions(role)).not.toContain(permission);
        expect(getUserPermissions(user)).not.toContain(permission);
        expect(hasPermission(user, permission)).toBe(false);
        expect(() => requirePermission(user, permission)).toThrow('Permission denied');
      }
      expect(hasAnyPermission(user, [...EXPLICIT_USER_PERMISSIONS])).toBe(false);
      expect(hasAllPermissions(user, [...EXPLICIT_USER_PERMISSIONS])).toBe(false);
      expect(() => requireAnyPermission(user, [...EXPLICIT_USER_PERMISSIONS])).toThrow('Permission denied');
      expect(() => requireAllPermissions(user, [...EXPLICIT_USER_PERMISSIONS])).toThrow('Permission denied');
    });

    it.each(ADMIN_ROLES)('%s needs a separate explicit grant for each own-scope permission', role => {
      for (const granted of EXPLICIT_USER_PERMISSIONS) {
        const user = { ...createTestUser(role), permissions: [granted] };
        for (const permission of EXPLICIT_USER_PERMISSIONS) {
          expect(hasPermission(user, permission)).toBe(permission === granted);
          expect(getUserPermissions(user).includes(permission)).toBe(permission === granted);
        }
        expect(hasAnyPermission(user, [...EXPLICIT_USER_PERMISSIONS])).toBe(true);
        expect(hasAllPermissions(user, [...EXPLICIT_USER_PERMISSIONS])).toBe(false);
        expect(() => requirePermission(user, granted)).not.toThrow();
        expect(() => requireAnyPermission(user, [...EXPLICIT_USER_PERMISSIONS])).not.toThrow();
        expect(() => requireAllPermissions(user, [...EXPLICIT_USER_PERMISSIONS])).toThrow('Permission denied');

        user.permissions = [];
        expect(hasPermission(user, granted)).toBe(false);
        expect(getUserPermissions(user)).not.toContain(granted);
      }
    });

    it('does not turn own-scope grants into administrative or other-user authority', () => {
      const user = { ...member, permissions: [...EXPLICIT_USER_PERMISSIONS] };
      expect(hasAllPermissions(user, [...EXPLICIT_USER_PERMISSIONS])).toBe(true);
      expect(() => requireAllPermissions(user, [...EXPLICIT_USER_PERMISSIONS])).not.toThrow();
      expect(user.role).toBe('member');
      for (const permission of [
        PERMISSIONS.ADMIN_CONTENT_PUBLISH,
        PERMISSIONS.ADMIN_CONTENT_MANAGE,
        PERMISSIONS.ADMIN_CONTENT_MODERATE,
        PERMISSIONS.ADMIN_CONTENT_DELETE,
        PERMISSIONS.ADMIN_FEDERATION_VIEW,
        PERMISSIONS.ADMIN_FEDERATION_DELIVER,
        PERMISSIONS.ADMIN_USERS_MANAGE,
        PERMISSIONS.ADMIN_USERS_DELETE,
      ]) {
        expect(hasPermission(user, permission)).toBe(false);
      }
      expect(canCreatePublicContent(user.role)).toBe(false);
      expect(canDeliverFederation(user.role)).toBe(false);
      expect(getAllowedVisibilityOptions(user.role)).toEqual(getAllowedVisibilityOptions(member.role));
    });
  });

  describe('hasAnyPermission', () => {
    it('should return true if user has at least one permission', () => {
      expect(hasAnyPermission(editor, [PERMISSIONS.ADMIN_CONTENT_MANAGE, PERMISSIONS.ADMIN_USERS_MANAGE])).toBe(true);
      expect(hasAnyPermission(viewer, [PERMISSIONS.ADMIN_ACCESS, PERMISSIONS.ADMIN_USERS_MANAGE])).toBe(true);
    });

    it('should return false if user has none of the permissions', () => {
      expect(hasAnyPermission(viewer, [PERMISSIONS.ADMIN_USERS_MANAGE, PERMISSIONS.ADMIN_CONTENT_MANAGE])).toBe(false);
    });
  });

  describe('hasAllPermissions', () => {
    it('should return true if user has all permissions', () => {
      expect(hasAllPermissions(editor, [PERMISSIONS.ADMIN_ACCESS, PERMISSIONS.ADMIN_CONTENT_VIEW])).toBe(true);
    });

    it('should return false if user is missing any permission', () => {
      expect(hasAllPermissions(viewer, [PERMISSIONS.ADMIN_ACCESS, PERMISSIONS.ADMIN_USERS_MANAGE])).toBe(false);
    });
  });

  describe('getRolePermissions', () => {
    it('should return all administrative permissions for super_admin', () => {
      const perms = getRolePermissions('super_admin');
      expect(perms).toContain(PERMISSIONS.ADMIN_SECURITY_MANAGE);
      expect(perms).toContain(PERMISSIONS.ADMIN_USERS_MANAGE);
      expect(perms).toContain(PERMISSIONS.ADMIN_CONTENT_MANAGE);
    });

    it('should return limited permissions for viewer', () => {
      const perms = getRolePermissions('viewer');
      expect(perms).toContain(PERMISSIONS.ADMIN_ACCESS);
      expect(perms).toContain(PERMISSIONS.ADMIN_ANALYTICS_VIEW);
      expect(perms).not.toContain(PERMISSIONS.ADMIN_USERS_MANAGE);
      expect(perms).not.toContain(PERMISSIONS.ADMIN_SECURITY_MANAGE);
    });

    it('should return event permissions for event_manager', () => {
      const perms = getRolePermissions('event_manager');
      expect(perms).toContain(PERMISSIONS.ADMIN_EVENTS_VIEW);
      expect(perms).toContain(PERMISSIONS.ADMIN_EVENTS_MANAGE);
    });

    it('should return moderator permissions', () => {
      const perms = getRolePermissions('moderator');
      expect(perms).toContain(PERMISSIONS.ADMIN_CONTENT_MODERATE);
      expect(perms).toContain(PERMISSIONS.ADMIN_USERS_VIEW);
    });
  });

  describe('canManageRole', () => {
    it('should allow super_admin to manage all roles', () => {
      expect(canManageRole('super_admin', 'admin')).toBe(true);
      expect(canManageRole('super_admin', 'moderator')).toBe(true);
      expect(canManageRole('super_admin', 'viewer')).toBe(true);
    });

    it('should allow admin to manage lower roles but not super_admin', () => {
      expect(canManageRole('admin', 'moderator')).toBe(true);
      expect(canManageRole('admin', 'viewer')).toBe(true);
      expect(canManageRole('admin', 'super_admin')).toBe(false);
      expect(canManageRole('admin', 'admin')).toBe(false);
    });

    it('should not allow viewer to manage any role', () => {
      expect(canManageRole('viewer', 'viewer')).toBe(false);
      expect(canManageRole('viewer', 'member')).toBe(false);
    });
  });
});

describe('Content Visibility', () => {
  describe('canViewContent', () => {
    it('should allow anyone to view public content', () => {
      expect(canViewContent('public', undefined)).toBe(true);
      expect(canViewContent('public', 'viewer')).toBe(true);
    });

    it('should only allow members to view members-only content', () => {
      expect(canViewContent('members', undefined)).toBe(false);
      expect(canViewContent('members', 'viewer')).toBe(false);
      expect(canViewContent('members', 'member')).toBe(true);
      expect(canViewContent('members', 'admin')).toBe(true);
    });

    it('should only allow admins to view admin content', () => {
      expect(canViewContent('admin', 'member')).toBe(false);
      expect(canViewContent('admin', 'moderator')).toBe(true);
      expect(canViewContent('admin', 'admin')).toBe(true);
    });

    it('should only allow owner to view private content', () => {
      expect(canViewContent('private', 'admin', 'author-1', 'user-1')).toBe(false);
      expect(canViewContent('private', 'admin', 'user-1', 'user-1')).toBe(true);
      expect(canViewContent('private', 'super_admin', 'author-1', 'user-1')).toBe(true);
    });
  });

  describe('filterContentByVisibility', () => {
    const testContent = [
      { id: '1', visibility: 'public', authorId: 'author-1' },
      { id: '2', visibility: 'members', authorId: 'author-1' },
      { id: '3', visibility: 'admin', authorId: 'author-1' },
      { id: '4', visibility: 'private', authorId: 'user-1' },
    ];

    it('should filter to only public for anonymous users', () => {
      const filtered = filterContentByVisibility(testContent, undefined);
      expect(filtered).toHaveLength(1);
      expect(filtered[0].id).toBe('1');
    });

    it('should include members content for members', () => {
      const filtered = filterContentByVisibility(testContent, 'member', 'user-1');
      expect(filtered).toHaveLength(3); 
      expect(filtered.map(c => c.id)).toContain('1');
      expect(filtered.map(c => c.id)).toContain('2');
      expect(filtered.map(c => c.id)).toContain('4');
    });

    it('should include admin content for admins', () => {
      const filtered = filterContentByVisibility(testContent, 'admin', 'user-1');
      expect(filtered).toHaveLength(4); 
    });
  });

  describe('getAllowedVisibilityOptions', () => {
    it('should return empty array for viewer', () => {
      const options = getAllowedVisibilityOptions('viewer');
      expect(options).toHaveLength(0);
    });

    it('should include members and private for members (but not public)', () => {
      const options = getAllowedVisibilityOptions('member');
      expect(options).toContain('members');
      expect(options).toContain('private');
      expect(options).not.toContain('public');
    });

    it('should include public, members, private for contributors', () => {
      const options = getAllowedVisibilityOptions('contributor');
      expect(options).toContain('public');
      expect(options).toContain('members');
      expect(options).toContain('private');
      expect(options).not.toContain('admin');
    });

    it('should include admin visibility for admins', () => {
      const options = getAllowedVisibilityOptions('admin');
      expect(options).toContain('admin');
      expect(options).toContain('public');
      expect(options).toContain('members');
      expect(options).toContain('private');
    });
  });
});

describe('Member Role Detection', () => {
  describe('isMemberRole', () => {
    it('should return true only for member role', () => {
      expect(isMemberRole('member')).toBe(true);
    });

    it('should return false for roles other than member', () => {
      expect(isMemberRole('contributor')).toBe(false);
      expect(isMemberRole('editor')).toBe(false);
      expect(isMemberRole('admin')).toBe(false);
    });

    it('should return false for viewer', () => {
      expect(isMemberRole('viewer')).toBe(false);
    });
  });
});
