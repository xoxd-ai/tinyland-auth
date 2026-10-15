// RBAC invariants P1/P2/P3 (TIN-2435, operator-ratified 2026-07-04) plus
// the pinned capability-lattice counterexamples (TIN-1606 precedent) and
// the full role x predicate derivation matrix.
//
// These tests are deliberately DETERMINISTIC and EXHAUSTIVE (no random
// property sampling): the whole role/permission space is 8 roles x 25
// permission strings (23 role-granted, 2 explicit-only), so we enumerate it.
//
// 0.5.0 (TIN-2637/TIN-2638, operator-ratified 2026-07-07): the ninth
// feature domain `federation` with `admin.federation.view` and
// `admin.federation.deliver`, anchored at moderator on the governance
// spine (moderator, admin, super_admin hold it; no specialist does).

import { describe, it, expect } from 'vitest';
import {
  ADMIN_ROLES,
  ROLE_HIERARCHY,
  type AdminRole,
} from '../src/types/auth.js';
import {
  PERMISSIONS,
  EXPLICIT_USER_PERMISSIONS,
  ROLE_PERMISSIONS,
  MEMBER_SELF_SERVICE_CORE,
  FEATURE_DOMAINS,
  PERMISSION_FEATURE_DOMAIN,
  ROLE_CHARTER,
} from '../src/types/permissions.js';
import {
  canManageRole,
  canViewPosts,
  canCreatePosts,
  canEditPosts,
  canDeletePosts,
  canViewEvents,
  canCreateEvents,
  canEditEvents,
  canDeleteEvents,
  canViewProfiles,
  canCreateProfiles,
  canEditOwnProfile,
  canEditAnyProfile,
  canDeleteProfiles,
  canViewUsers,
  canManageUsers,
  canViewVideos,
  canCreateVideos,
  canEditVideos,
  canDeleteVideos,
  canCreatePublicContent,
  canCreateMemberOnlyContent,
  canFeatureProfile,
  canEditOwnContent,
  canDeleteOwnContent,
  canEditContent,
  canDeleteContent,
  isMemberRole,
  canViewMemberOnlyContent,
  canDeliverFederation,
  getAllowedVisibilityOptions,
  canViewContent,
} from '../src/core/permissions/index.js';

const permissionSet = (role: AdminRole): Set<string> =>
  new Set(ROLE_PERMISSIONS[role]);

const holdsAll = (role: AdminRole, permissions: readonly string[]): boolean =>
  permissions.every(permission => permissionSet(role).has(permission));

describe('P1: management order is ROLE_HIERARCHY (exhaustive, 64 pairs)', () => {
  it('canManageRole(actor, target) is exactly rank(actor) > rank(target)', () => {
    for (const actor of ADMIN_ROLES) {
      for (const target of ADMIN_ROLES) {
        expect(
          canManageRole(actor, target),
          `canManageRole(${actor}, ${target})`,
        ).toBe(ROLE_HIERARCHY[actor] > ROLE_HIERARCHY[target]);
      }
    }
  });

  it('rejects unknown roles on either side', () => {
    expect(canManageRole('owner', 'viewer')).toBe(false);
    expect(canManageRole('super_admin', 'owner')).toBe(false);
  });
});

describe('P2: member self-service core is a floor for every role >= member', () => {
  it('MEMBER_SELF_SERVICE_CORE is the member row, by construction', () => {
    expect([...MEMBER_SELF_SERVICE_CORE]).toEqual(ROLE_PERMISSIONS.member);
  });

  it('the core is exactly the ratified triple (TIN-2435)', () => {
    expect([...MEMBER_SELF_SERVICE_CORE].sort()).toEqual([
      PERMISSIONS.ADMIN_ACCESS,
      PERMISSIONS.ADMIN_CONTENT_VIEW,
      PERMISSIONS.ADMIN_EVENTS_VIEW,
    ].sort());
  });

  it('every role ranked at or above member holds the full core', () => {
    const rolesAtOrAboveMember = ADMIN_ROLES.filter(
      role => ROLE_HIERARCHY[role] >= ROLE_HIERARCHY.member,
    );

    expect(rolesAtOrAboveMember).toEqual([
      'super_admin',
      'admin',
      'moderator',
      'editor',
      'event_manager',
      'contributor',
      'member',
    ]);

    for (const role of rolesAtOrAboveMember) {
      for (const permission of MEMBER_SELF_SERVICE_CORE) {
        expect(
          permissionSet(role).has(permission),
          `${role} must hold core permission ${permission}`,
        ).toBe(true);
      }
    }
  });
});

describe('P3: feature-domain registry covers the permission vocabulary exactly', () => {
  it('registry keys == PERMISSIONS values (both directions)', () => {
    const registryKeys = new Set(Object.keys(PERMISSION_FEATURE_DOMAIN));
    const permissionValues = new Set<string>(Object.values(PERMISSIONS));

    expect([...registryKeys].sort()).toEqual([...permissionValues].sort());
  });

  it('role grants and explicit-only permissions form disjoint, exhaustive registry partitions', () => {
    const granted = new Set<string>();
    for (const role of ADMIN_ROLES) {
      for (const permission of ROLE_PERMISSIONS[role]) {
        granted.add(permission);
      }
    }
    const registryKeys = new Set(Object.keys(PERMISSION_FEATURE_DOMAIN));
    const explicitOnly = new Set<string>(EXPLICIT_USER_PERMISSIONS);

    for (const permission of granted) {
      expect(
        registryKeys.has(permission),
        `granted permission ${permission} must be registered`,
      ).toBe(true);
    }
    for (const permission of explicitOnly) {
      expect(registryKeys.has(permission)).toBe(true);
      expect(granted.has(permission), `${permission} must have no default role grant`).toBe(false);
    }
    for (const permission of registryKeys) {
      expect(
        granted.has(permission) || explicitOnly.has(permission),
        `registered permission ${permission} must be role-granted or explicit-only`,
      ).toBe(true);
    }
  });

  it('every registry value is a ratified feature domain derived from the string prefix', () => {
    for (const [permission, domain] of Object.entries(PERMISSION_FEATURE_DOMAIN)) {
      expect(FEATURE_DOMAINS).toContain(domain);
      const expectedDomain =
        permission === 'admin.access' ? 'access'
          : permission.startsWith('admin.') ? permission.split('.')[1]
            : permission.split('.')[0];
      expect(domain, `domain tag for ${permission}`).toBe(expectedDomain);
    }
  });

  it('own-scope permissions reuse content and federation without widening the member floor', () => {
    expect(PERMISSION_FEATURE_DOMAIN['content.own.publish']).toBe('content');
    expect(PERMISSION_FEATURE_DOMAIN['federation.own.deliver']).toBe('federation');
    for (const permission of EXPLICIT_USER_PERMISSIONS) {
      expect(MEMBER_SELF_SERVICE_CORE).not.toContain(permission);
    }
  });

  it('ROLE_CHARTER tags every role, spine ranks mirror ROLE_HIERARCHY, specialists are exactly the ratified three', () => {
    expect(Object.keys(ROLE_CHARTER).sort()).toEqual([...ADMIN_ROLES].sort());

    for (const role of ADMIN_ROLES) {
      expect(ROLE_CHARTER[role].rank).toBe(ROLE_HIERARCHY[role]);
    }

    const specialists = ADMIN_ROLES.filter(
      role => ROLE_CHARTER[role].axis === 'specialist',
    ).sort();
    expect(specialists).toEqual(['contributor', 'editor', 'event_manager']);
  });
});

describe('federation domain (0.5.0, TIN-2637/TIN-2638): exact holder sets', () => {
  const FEDERATION_HOLDERS: readonly AdminRole[] = ['super_admin', 'admin', 'moderator'];

  it('the ratified domain set is exactly the TIN-2435 eight plus federation (TIN-2638)', () => {
    expect([...FEATURE_DOMAINS]).toEqual([
      'access',
      'users',
      'content',
      'events',
      'analytics',
      'settings',
      'security',
      'logs',
      'federation',
    ]);
  });

  it('both federation permissions map to the federation domain', () => {
    expect(PERMISSION_FEATURE_DOMAIN['admin.federation.view']).toBe('federation');
    expect(PERMISSION_FEATURE_DOMAIN['admin.federation.deliver']).toBe('federation');
  });

  it('exactly {moderator, admin, super_admin} hold admin.federation.deliver (exhaustive over all 8 roles)', () => {
    for (const role of ADMIN_ROLES) {
      expect(
        permissionSet(role).has(PERMISSIONS.ADMIN_FEDERATION_DELIVER),
        `${role} holds admin.federation.deliver`,
      ).toBe(FEDERATION_HOLDERS.includes(role));
    }
  });

  it('exactly {moderator, admin, super_admin} hold admin.federation.view (exhaustive over all 8 roles)', () => {
    for (const role of ADMIN_ROLES) {
      expect(
        permissionSet(role).has(PERMISSIONS.ADMIN_FEDERATION_VIEW),
        `${role} holds admin.federation.view`,
      ).toBe(FEDERATION_HOLDERS.includes(role));
    }
  });

  it('R1 spine propagation: every governance-spine role ranked at or above moderator holds deliver, and no specialist does', () => {
    for (const role of ADMIN_ROLES) {
      const onSpineAtOrAboveModerator =
        ROLE_CHARTER[role].axis === 'governance-spine' &&
        ROLE_HIERARCHY[role] >= ROLE_HIERARCHY.moderator;
      expect(
        permissionSet(role).has(PERMISSIONS.ADMIN_FEDERATION_DELIVER),
        `${role}: deliver iff governance-spine rank >= moderator`,
      ).toBe(onSpineAtOrAboveModerator);
    }
  });
});

describe('ratified lattice: chain-monotonicity is NOT an invariant', () => {
  // Operator ratification (TIN-2435 thread, 2026-07-04; precedent TIN-1606,
  // decision-of-record 2026-05-25): ROLE_PERMISSIONS is an intentional
  // lattice. Governance rank orders who manages whom; capabilities are
  // feature-scoped and are NOT required to nest by rank. Do not "fix" the
  // pinned counterexamples below into superset relations - the non-nesting
  // is product policy, and a PBT asserting rank-superset monotonicity is
  // asserting a false property (the pre-TIN-2435 flaky test did exactly
  // that).

  const isRankSuperset = (higher: AdminRole, lower: AdminRole): boolean =>
    ROLE_HIERARCHY[higher] > ROLE_HIERARCHY[lower] &&
    holdsAll(higher, ROLE_PERMISSIONS[lower]);

  it('pinned: TIN-1606 pair - contributor never inherits event management', () => {
    expect(ROLE_PERMISSIONS.event_manager).toContain(PERMISSIONS.ADMIN_EVENTS_MANAGE);
    expect(ROLE_PERMISSIONS.contributor).not.toContain(PERMISSIONS.ADMIN_EVENTS_MANAGE);
  });

  it('pinned: editor outranks event_manager but is not a superset of it', () => {
    expect(ROLE_HIERARCHY.editor).toBeGreaterThan(ROLE_HIERARCHY.event_manager);
    expect(ROLE_PERMISSIONS.editor).not.toContain(PERMISSIONS.ADMIN_EVENTS_MANAGE);
    expect(isRankSuperset('editor', 'event_manager')).toBe(false);
  });

  it('pinned: admin outranks moderator but does not hold content moderation', () => {
    expect(ROLE_HIERARCHY.admin).toBeGreaterThan(ROLE_HIERARCHY.moderator);
    expect(ROLE_PERMISSIONS.admin).not.toContain(PERMISSIONS.ADMIN_CONTENT_MODERATE);
    expect(isRankSuperset('admin', 'moderator')).toBe(false);
  });

  it('pinned: member outranks viewer but does not hold analytics view', () => {
    expect(ROLE_HIERARCHY.member).toBeGreaterThan(ROLE_HIERARCHY.viewer);
    expect(ROLE_PERMISSIONS.member).not.toContain(PERMISSIONS.ADMIN_ANALYTICS_VIEW);
    expect(isRankSuperset('member', 'viewer')).toBe(false);
  });

  it('super_admin remains a superset of every role', () => {
    for (const role of ADMIN_ROLES) {
      if (role === 'super_admin') continue;
      expect(
        holdsAll('super_admin', ROLE_PERMISSIONS[role]),
        `super_admin must hold everything ${role} holds`,
      ).toBe(true);
    }
  });
});

describe('role x predicate derivation matrix (behavior lock)', () => {
  // The full predicate matrix, locked value-by-value. This is the
  // before/after proof for the TIN-2435 predicate derivation: every cell
  // matches the pre-derivation hand-array behavior EXCEPT the four
  // intentional deltas marked "DELTA", which are the P2 member-core
  // flow-through (TIN-2435):
  //   - canCreateEvents: moderator, editor, contributor false -> true
  //     (own-event creation follows admin.events.view, which those roles
  //     gained in the P2 data reconciliation)
  //   - canDeleteOwnContent: moderator false -> true (own-content
  //     self-service floors at the member core; the previous exclusion of
  //     moderator was hand-array drift)
  const ROLES = [
    'super_admin',
    'admin',
    'moderator',
    'editor',
    'event_manager',
    'contributor',
    'member',
    'viewer',
  ] as const;

  type PredicateRow = [
    (role: AdminRole | string) => boolean,
    Record<(typeof ROLES)[number], boolean>,
  ];

  const matrix: Record<string, PredicateRow> = {
    canViewPosts: [canViewPosts, {
      super_admin: true, admin: true, moderator: true, editor: true,
      event_manager: true, contributor: true, member: true, viewer: true,
    }],
    canCreatePosts: [canCreatePosts, {
      super_admin: true, admin: true, moderator: true, editor: true,
      event_manager: true, contributor: true, member: true, viewer: false,
    }],
    canEditPosts: [canEditPosts, {
      super_admin: true, admin: true, moderator: false, editor: true,
      event_manager: false, contributor: false, member: false, viewer: false,
    }],
    canDeletePosts: [canDeletePosts, {
      super_admin: true, admin: true, moderator: false, editor: false,
      event_manager: false, contributor: false, member: false, viewer: false,
    }],
    canViewEvents: [canViewEvents, {
      super_admin: true, admin: true, moderator: true, editor: true,
      event_manager: true, contributor: true, member: true, viewer: true,
    }],
    canCreateEvents: [canCreateEvents, {
      super_admin: true, admin: true,
      moderator: true, // DELTA (P2 flow-through)
      editor: true, // DELTA (P2 flow-through)
      event_manager: true,
      contributor: true, // DELTA (P2 flow-through)
      member: true, viewer: false,
    }],
    canEditEvents: [canEditEvents, {
      super_admin: true, admin: true, moderator: false, editor: false,
      event_manager: true, contributor: false, member: false, viewer: false,
    }],
    canDeleteEvents: [canDeleteEvents, {
      super_admin: true, admin: true, moderator: false, editor: false,
      event_manager: false, contributor: false, member: false, viewer: false,
    }],
    canViewProfiles: [canViewProfiles, {
      super_admin: true, admin: true, moderator: true, editor: true,
      event_manager: true, contributor: true, member: true, viewer: true,
    }],
    canCreateProfiles: [canCreateProfiles, {
      super_admin: true, admin: true, moderator: false, editor: false,
      event_manager: false, contributor: false, member: false, viewer: false,
    }],
    canEditOwnProfile: [canEditOwnProfile, {
      super_admin: true, admin: true, moderator: true, editor: true,
      event_manager: true, contributor: true, member: true, viewer: true,
    }],
    canEditAnyProfile: [canEditAnyProfile, {
      super_admin: true, admin: true, moderator: false, editor: false,
      event_manager: false, contributor: false, member: false, viewer: false,
    }],
    canDeleteProfiles: [canDeleteProfiles, {
      super_admin: true, admin: false, moderator: false, editor: false,
      event_manager: false, contributor: false, member: false, viewer: false,
    }],
    canViewUsers: [canViewUsers, {
      super_admin: true, admin: true, moderator: true, editor: false,
      event_manager: false, contributor: false, member: false, viewer: false,
    }],
    canManageUsers: [canManageUsers, {
      super_admin: true, admin: true, moderator: false, editor: false,
      event_manager: false, contributor: false, member: false, viewer: false,
    }],
    canViewVideos: [canViewVideos, {
      super_admin: true, admin: true, moderator: true, editor: true,
      event_manager: true, contributor: true, member: true, viewer: true,
    }],
    canCreateVideos: [canCreateVideos, {
      super_admin: true, admin: true, moderator: false, editor: true,
      event_manager: false, contributor: true, member: false, viewer: false,
    }],
    canEditVideos: [canEditVideos, {
      super_admin: true, admin: true, moderator: false, editor: true,
      event_manager: false, contributor: false, member: false, viewer: false,
    }],
    canDeleteVideos: [canDeleteVideos, {
      super_admin: true, admin: true, moderator: false, editor: false,
      event_manager: false, contributor: false, member: false, viewer: false,
    }],
    canCreatePublicContent: [canCreatePublicContent, {
      super_admin: true, admin: true, moderator: true, editor: true,
      event_manager: true, contributor: true, member: false, viewer: false,
    }],
    canCreateMemberOnlyContent: [canCreateMemberOnlyContent, {
      super_admin: true, admin: true, moderator: true, editor: true,
      event_manager: true, contributor: true, member: true, viewer: false,
    }],
    canFeatureProfile: [canFeatureProfile, {
      super_admin: true, admin: true, moderator: false, editor: false,
      event_manager: false, contributor: false, member: false, viewer: false,
    }],
    canEditOwnContent: [canEditOwnContent, {
      super_admin: true, admin: true, moderator: true, editor: true,
      event_manager: true, contributor: true, member: true, viewer: false,
    }],
    canDeleteOwnContent: [canDeleteOwnContent, {
      super_admin: true, admin: true,
      moderator: true, // DELTA (member-core self-service floor)
      editor: true,
      event_manager: true, contributor: true, member: true, viewer: false,
    }],
    canEditContent: [canEditContent, {
      super_admin: true, admin: true, moderator: true, editor: true,
      event_manager: false, contributor: false, member: false, viewer: false,
    }],
    canDeleteContent: [canDeleteContent, {
      super_admin: true, admin: true, moderator: false, editor: false,
      event_manager: false, contributor: false, member: false, viewer: false,
    }],
    isMemberRole: [isMemberRole, {
      super_admin: false, admin: false, moderator: false, editor: false,
      event_manager: false, contributor: false, member: true, viewer: false,
    }],
    canViewMemberOnlyContent: [canViewMemberOnlyContent, {
      super_admin: true, admin: true, moderator: true, editor: true,
      event_manager: true, contributor: true, member: true, viewer: false,
    }],
    canDeliverFederation: [canDeliverFederation, {
      super_admin: true, admin: true, moderator: true, editor: false,
      event_manager: false, contributor: false, member: false, viewer: false,
    }],
  };

  it('matches the locked matrix cell-by-cell', () => {
    for (const [name, [predicate, expected]] of Object.entries(matrix)) {
      for (const role of ROLES) {
        expect(
          predicate(role),
          `${name}(${role})`,
        ).toBe(expected[role]);
      }
    }
  });

  it('predicates reject unknown roles', () => {
    for (const [name, [predicate]] of Object.entries(matrix)) {
      if (name === 'isMemberRole') continue;
      expect(predicate('owner'), `${name}(owner)`).toBe(false);
    }
  });

  it('getAllowedVisibilityOptions matches the pre-derivation tiers exactly', () => {
    expect(getAllowedVisibilityOptions('super_admin')).toEqual(['public', 'members', 'admin', 'private']);
    expect(getAllowedVisibilityOptions('admin')).toEqual(['public', 'members', 'admin', 'private']);
    expect(getAllowedVisibilityOptions('moderator')).toEqual(['public', 'members', 'private']);
    expect(getAllowedVisibilityOptions('editor')).toEqual(['public', 'members', 'private']);
    expect(getAllowedVisibilityOptions('event_manager')).toEqual(['public', 'members', 'private']);
    expect(getAllowedVisibilityOptions('contributor')).toEqual(['public', 'members', 'private']);
    expect(getAllowedVisibilityOptions('member')).toEqual(['members', 'private']);
    expect(getAllowedVisibilityOptions('viewer')).toEqual([]);
    expect(getAllowedVisibilityOptions('owner')).toEqual([]);
  });

  it('canViewContent admin/members tiers match the pre-derivation sets exactly', () => {
    const adminVisibility: Record<string, boolean> = {
      super_admin: true, admin: true, moderator: true, editor: true,
      event_manager: true, contributor: false, member: false, viewer: false,
    };
    const membersVisibility: Record<string, boolean> = {
      super_admin: true, admin: true, moderator: true, editor: true,
      event_manager: true, contributor: true, member: true, viewer: false,
    };
    for (const role of ROLES) {
      expect(canViewContent('admin', role), `admin visibility for ${role}`).toBe(adminVisibility[role]);
      expect(canViewContent('members', role), `members visibility for ${role}`).toBe(membersVisibility[role]);
    }
  });
});
