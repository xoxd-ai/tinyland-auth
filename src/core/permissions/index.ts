








import { ROLE_HIERARCHY, isValidAdminRole, type AdminRole, type AdminUser } from '../../types/auth.js';
import { EXPLICIT_USER_PERMISSIONS, PERMISSIONS, ROLE_PERMISSIONS, type AdminPermission, type OwnPermission, type ContentVisibility } from '../../types/permissions.js';








export function getRolePermissions(role: AdminRole | string): string[] {
  const normalizedRole = role as AdminRole;
  return ROLE_PERMISSIONS[normalizedRole] || [PERMISSIONS.ADMIN_ACCESS];
}




export function hasPermission(user: AdminUser, permission: string): boolean {
  if (EXPLICIT_USER_PERMISSIONS.includes(permission as OwnPermission)) {
    return user.permissions?.includes(permission) === true;
  }
  if (user.role === 'super_admin') {
    return true;
  }
  if (user.permissions?.includes(permission)) {
    return true;
  }
  const rolePermissions = getRolePermissions(user.role);
  return rolePermissions.includes(permission);
}




export function hasAnyPermission(user: AdminUser, permissions: string[]): boolean {
  return permissions.some(permission => hasPermission(user, permission));
}




export function hasAllPermissions(user: AdminUser, permissions: string[]): boolean {
  return permissions.every(permission => hasPermission(user, permission));
}




export function requirePermission(user: AdminUser, permission: string): void {
  if (!hasPermission(user, permission)) {
    throw new Error(`Permission denied: ${permission} required`);
  }
}




export function requireAnyPermission(user: AdminUser, permissions: string[]): void {
  if (!hasAnyPermission(user, permissions)) {
    throw new Error(`Permission denied: one of [${permissions.join(', ')}] required`);
  }
}




export function requireAllPermissions(user: AdminUser, permissions: string[]): void {
  if (!hasAllPermissions(user, permissions)) {
    throw new Error(`Permission denied: all of [${permissions.join(', ')}] required`);
  }
}




export function getUserPermissions(user: AdminUser): string[] {
  if (user.role === 'super_admin') {
    return Object.values(PERMISSIONS).filter(permission => hasPermission(user, permission));
  }
  const rolePerms = getRolePermissions(user.role);
  const userPerms = user.permissions || [];
  return [...new Set([...rolePerms, ...userPerms])];
}




export function canManageRole(actorRole: AdminRole | string, targetRole: AdminRole | string): boolean {
  const normalizedActor = normalizeRole(actorRole);
  const normalizedTarget = normalizeRole(targetRole);

  if (
    !isValidAdminRole(normalizedActor) ||
    !isValidAdminRole(normalizedTarget)
  ) {
    return false;
  }

  return ROLE_HIERARCHY[normalizedActor] > ROLE_HIERARCHY[normalizedTarget];
}




export function isValidPermission(permission: string): boolean {
  return Object.values(PERMISSIONS).includes(permission as typeof PERMISSIONS[keyof typeof PERMISSIONS]);
}




export function getPermissionDisplayName(permission: string): string {
  const displayNames: Record<string, string> = {
    [PERMISSIONS.ADMIN_ACCESS]: 'Admin Panel Access',
    [PERMISSIONS.ADMIN_USERS_VIEW]: 'View Users',
    [PERMISSIONS.ADMIN_USERS_MANAGE]: 'Manage Users',
    [PERMISSIONS.ADMIN_USERS_DELETE]: 'Delete Users',
    [PERMISSIONS.ADMIN_CONTENT_VIEW]: 'View Content',
    [PERMISSIONS.ADMIN_CONTENT_PUBLISH]: 'Publish Public Content',
    [PERMISSIONS.ADMIN_CONTENT_MEDIA_CREATE]: 'Create Media Content',
    [PERMISSIONS.ADMIN_CONTENT_MANAGE]: 'Manage Content',
    [PERMISSIONS.ADMIN_CONTENT_MODERATE]: 'Moderate Content',
    [PERMISSIONS.ADMIN_CONTENT_DELETE]: 'Delete Content',
    [PERMISSIONS.ADMIN_EVENTS_VIEW]: 'View Events',
    [PERMISSIONS.ADMIN_EVENTS_MANAGE]: 'Manage Events',
    [PERMISSIONS.ADMIN_EVENTS_DELETE]: 'Delete Events',
    [PERMISSIONS.ADMIN_ANALYTICS_VIEW]: 'View Analytics',
    [PERMISSIONS.ADMIN_ANALYTICS_EXPORT]: 'Export Analytics',
    [PERMISSIONS.ADMIN_SETTINGS_VIEW]: 'View Settings',
    [PERMISSIONS.ADMIN_SETTINGS_MANAGE]: 'Manage Settings',
    [PERMISSIONS.ADMIN_SECURITY_VIEW]: 'View Security',
    [PERMISSIONS.ADMIN_SECURITY_MANAGE]: 'Manage Security',
    [PERMISSIONS.ADMIN_LOGS_VIEW]: 'View Logs',
    [PERMISSIONS.ADMIN_LOGS_EXPORT]: 'Export Logs',
    [PERMISSIONS.ADMIN_FEDERATION_VIEW]: 'View Federation',
    [PERMISSIONS.ADMIN_FEDERATION_DELIVER]: 'Deliver Federation',
    [PERMISSIONS.CONTENT_OWN_PUBLISH]: 'Publish Own Public Content',
    [PERMISSIONS.FEDERATION_OWN_DELIVER]: 'Deliver Own Federation Content',
  };
  return displayNames[permission] || permission;
}





// Every can* predicate below derives from ROLE_PERMISSIONS (the SSOT
// capability lattice) instead of hand-maintained role arrays. The role
// arrays were the tinyland.dev#628 anti-pattern: independently maintained
// lists that drift from the hierarchy/matrix they claim to encode
// (TIN-2429, TIN-2435).

function normalizeRole(role: AdminRole | string): string {
  return String(role).toLowerCase().replace(/-/g, '_');
}

function roleHoldsPermission(role: AdminRole | string, permission: AdminPermission): boolean {
  const normalized = normalizeRole(role);
  if (!isValidAdminRole(normalized)) {
    return false;
  }
  return ROLE_PERMISSIONS[normalized].includes(permission);
}

function roleHoldsAnyPermission(role: AdminRole | string, permissions: AdminPermission[]): boolean {
  return permissions.some(permission => roleHoldsPermission(role, permission));
}

// Domain list views floor at admin.access: every valid role may see the
// admin-surface list views, matching the pre-derivation ALL_ROLES behavior.
export function canViewPosts(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_ACCESS);
}

// Own-content authoring (create / edit own / delete own / member-only
// visibility) derives from admin.content.view, the member self-service
// core marker (TIN-2435 P2): every role at or above member self-services
// its own content.
export function canCreatePosts(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_CONTENT_VIEW);
}

export function canEditPosts(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_CONTENT_MANAGE);
}

export function canDeletePosts(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_CONTENT_DELETE);
}


export function canViewEvents(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_ACCESS);
}

// Own-event creation derives from admin.events.view, the member
// self-service core marker for the events domain (TIN-2435 P2).
export function canCreateEvents(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_EVENTS_VIEW);
}

export function canEditEvents(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_EVENTS_MANAGE);
}

export function canDeleteEvents(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_EVENTS_DELETE);
}


export function canViewProfiles(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_ACCESS);
}

// Profile administration is user management (users feature domain).
export function canCreateProfiles(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_USERS_MANAGE);
}

export function canEditOwnProfile(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_ACCESS);
}

export function canEditAnyProfile(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_USERS_MANAGE);
}

export function canDeleteProfiles(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_USERS_DELETE);
}


export function canViewUsers(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_USERS_VIEW);
}

export function canManageUsers(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_USERS_MANAGE);
}


export function canViewVideos(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_ACCESS);
}

export function canCreateVideos(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_CONTENT_MEDIA_CREATE);
}

export function canEditVideos(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_CONTENT_MANAGE);
}

export function canDeleteVideos(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_CONTENT_DELETE);
}





export function canCreatePublicContent(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_CONTENT_PUBLISH);
}

export function canCreateMemberOnlyContent(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_CONTENT_VIEW);
}

export function canFeatureProfile(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_USERS_MANAGE);
}

export function canEditOwnContent(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_CONTENT_VIEW);
}

// Intentional delta vs the pre-derivation array (TIN-2435): moderator now
// holds own-content deletion. Own-content self-service floors at the
// member core, and moderator ranks above member; its previous exclusion
// was hand-array drift, not policy.
export function canDeleteOwnContent(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_CONTENT_VIEW);
}

export function canEditContent(role: AdminRole | string): boolean {
  return roleHoldsAnyPermission(role, [
    PERMISSIONS.ADMIN_CONTENT_MANAGE,
    PERMISSIONS.ADMIN_CONTENT_MODERATE,
  ]);
}

export function canDeleteContent(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_CONTENT_DELETE);
}

export function isMemberRole(role: AdminRole | string): boolean {
  return normalizeRole(role) === 'member';
}

export function canViewMemberOnlyContent(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_CONTENT_VIEW);
}

// Federation delivery (TIN-2637/TIN-2638, ratified 2026-07-07): derives
// from ROLE_PERMISSIONS via the SSOT helper like every other predicate —
// never a hardcoded role array (the tinyland.dev#628 anti-pattern class).
export function canDeliverFederation(role: AdminRole | string): boolean {
  return roleHoldsPermission(role, PERMISSIONS.ADMIN_FEDERATION_DELIVER);
}

export function getAllowedVisibilityOptions(role: AdminRole | string): string[] {
  if (!canCreateMemberOnlyContent(role)) {
    return [];
  }

  const options: string[] = [];

  if (canCreatePublicContent(role)) {
    options.push('public');
  }

  options.push('members');

  // Admin-only visibility authoring tracks the content-admin tier
  // (admin.content.delete holders): admin and super_admin today.
  if (canDeleteContent(role)) {
    options.push('admin');
  }

  options.push('private');

  return options;
}








export function canViewContent(
  visibility: ContentVisibility | string | undefined,
  userRole: AdminRole | string | null | undefined,
  authorId?: string | null,
  userId?: string | null
): boolean {
  const v = (visibility || 'public').toLowerCase();

  if (v === 'public') {
    return true;
  }

  if (!userRole) {
    return false;
  }

  const r = normalizeRole(userRole);

  if (r === 'super_admin') {
    return true;
  }

  if (v === 'private') {
    return userId != null && authorId != null && userId === authorId;
  }

  if (v === 'admin') {
    // Admin-visibility content is readable by domain managers: any role
    // holding a manage/moderate capability (super_admin returned above).
    return roleHoldsAnyPermission(r, [
      PERMISSIONS.ADMIN_CONTENT_MANAGE,
      PERMISSIONS.ADMIN_CONTENT_MODERATE,
      PERMISSIONS.ADMIN_EVENTS_MANAGE,
    ]);
  }

  if (v === 'members') {
    return roleHoldsPermission(r, PERMISSIONS.ADMIN_CONTENT_VIEW);
  }

  return false;
}




export function filterContentByVisibility<T extends { visibility?: string; authorId?: string }>(
  items: T[],
  userRole: AdminRole | string | null | undefined,
  userId?: string | null
): T[] {
  return items.filter(item =>
    canViewContent(item.visibility, userRole, item.authorId, userId)
  );
}





export {
  isContentOwner,
  canEditContent as canEditOwnedContent,
  canDeleteContent as canDeleteOwnedContent,
  requireContentEditPermission,
  requireContentDeletePermission,
  isSoleOwner,
  type OwnershipUser,
  type OwnedContent,
  type OwnershipError,
} from './ownership.js';





export { PERMISSIONS, ROLE_PERMISSIONS } from '../../types/permissions.js';
