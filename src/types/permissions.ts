

import type { AdminRole } from './auth.js';
import { ROLE_HIERARCHY } from './auth.js';




export type AdminPermission =
  | 'admin.access'
  | 'admin.users.view'
  | 'admin.users.manage'
  | 'admin.users.delete'
  | 'admin.content.view'
  | 'admin.content.publish'
  | 'admin.content.media_create'
  | 'admin.content.manage'
  | 'admin.content.moderate'
  | 'admin.content.delete'
  | 'admin.events.view'
  | 'admin.events.manage'
  | 'admin.events.delete'
  | 'admin.analytics.view'
  | 'admin.analytics.export'
  | 'admin.settings.view'
  | 'admin.settings.manage'
  | 'admin.security.view'
  | 'admin.security.manage'
  | 'admin.logs.view'
  | 'admin.logs.export'
  | 'admin.federation.view'
  | 'admin.federation.deliver';

// Own-scope capabilities are explicit user grants, never role defaults.
export type OwnPermission = 'content.own.publish' | 'federation.own.deliver';

export type Permission = AdminPermission | OwnPermission;



const ADMIN_PERMISSIONS = {
  ADMIN_ACCESS: 'admin.access',
  ADMIN_USERS_VIEW: 'admin.users.view',
  ADMIN_USERS_MANAGE: 'admin.users.manage',
  ADMIN_USERS_DELETE: 'admin.users.delete',
  ADMIN_CONTENT_VIEW: 'admin.content.view',
  ADMIN_CONTENT_PUBLISH: 'admin.content.publish',
  ADMIN_CONTENT_MEDIA_CREATE: 'admin.content.media_create',
  ADMIN_CONTENT_MANAGE: 'admin.content.manage',
  ADMIN_CONTENT_MODERATE: 'admin.content.moderate',
  ADMIN_CONTENT_DELETE: 'admin.content.delete',
  ADMIN_EVENTS_VIEW: 'admin.events.view',
  ADMIN_EVENTS_MANAGE: 'admin.events.manage',
  ADMIN_EVENTS_DELETE: 'admin.events.delete',
  ADMIN_ANALYTICS_VIEW: 'admin.analytics.view',
  ADMIN_ANALYTICS_EXPORT: 'admin.analytics.export',
  ADMIN_SETTINGS_VIEW: 'admin.settings.view',
  ADMIN_SETTINGS_MANAGE: 'admin.settings.manage',
  ADMIN_SECURITY_VIEW: 'admin.security.view',
  ADMIN_SECURITY_MANAGE: 'admin.security.manage',
  ADMIN_LOGS_VIEW: 'admin.logs.view',
  ADMIN_LOGS_EXPORT: 'admin.logs.export',
  ADMIN_FEDERATION_VIEW: 'admin.federation.view',
  ADMIN_FEDERATION_DELIVER: 'admin.federation.deliver',
} as const;

export const PERMISSIONS = {
  ...ADMIN_PERMISSIONS,
  CONTENT_OWN_PUBLISH: 'content.own.publish',
  FEDERATION_OWN_DELIVER: 'federation.own.deliver',
} as const satisfies Record<string, Permission>;

// These permissions require the current principal's permissions[] carrier,
// including for super_admin. Consumers must independently enforce ownership.
export const EXPLICIT_USER_PERMISSIONS: readonly OwnPermission[] = Object.freeze([
  PERMISSIONS.CONTENT_OWN_PUBLISH,
  PERMISSIONS.FEDERATION_OWN_DELIVER,
]);

// ROLE_PERMISSIONS is the single source of truth for role capabilities.
// It is an INTENTIONAL LATTICE (operator-ratified, TIN-2435; precedent
// TIN-1606): governance rank (ROLE_HIERARCHY) orders who manages whom,
// while capabilities are feature-scoped and do NOT nest by rank.
// Invariant P2 (TIN-2435): every role ranked at or above `member` holds
// MEMBER_SELF_SERVICE_CORE (the member row) as a floor.
export const ROLE_PERMISSIONS: Record<AdminRole, string[]> = {
  super_admin: Object.values(ADMIN_PERMISSIONS),

  admin: [
    PERMISSIONS.ADMIN_ACCESS,
    PERMISSIONS.ADMIN_USERS_VIEW,
    PERMISSIONS.ADMIN_USERS_MANAGE,
    PERMISSIONS.ADMIN_CONTENT_VIEW,
    PERMISSIONS.ADMIN_CONTENT_PUBLISH,
    PERMISSIONS.ADMIN_CONTENT_MEDIA_CREATE,
    PERMISSIONS.ADMIN_CONTENT_MANAGE,
    PERMISSIONS.ADMIN_CONTENT_DELETE,
    PERMISSIONS.ADMIN_EVENTS_VIEW,
    PERMISSIONS.ADMIN_EVENTS_MANAGE,
    PERMISSIONS.ADMIN_EVENTS_DELETE,
    PERMISSIONS.ADMIN_ANALYTICS_VIEW,
    PERMISSIONS.ADMIN_SETTINGS_VIEW,
    PERMISSIONS.ADMIN_LOGS_VIEW,
    // R1 (TIN-2637, ratified 2026-07-07): federation delivery is a
    // governance-spine capability; admin holds what moderator holds here.
    PERMISSIONS.ADMIN_FEDERATION_VIEW,
    PERMISSIONS.ADMIN_FEDERATION_DELIVER,
  ],

  moderator: [
    PERMISSIONS.ADMIN_ACCESS,
    PERMISSIONS.ADMIN_CONTENT_VIEW,
    PERMISSIONS.ADMIN_CONTENT_PUBLISH,
    PERMISSIONS.ADMIN_CONTENT_MODERATE,
    PERMISSIONS.ADMIN_USERS_VIEW,
    // P2 reconciliation (TIN-2435): member self-service core floor.
    PERMISSIONS.ADMIN_EVENTS_VIEW,
    PERMISSIONS.ADMIN_ANALYTICS_VIEW,
    PERMISSIONS.ADMIN_LOGS_VIEW,
    // R1 (TIN-2637, ratified 2026-07-07): moderator is the fedi/community
    // moderation role; it anchors federation delivery on the governance
    // spine (admin and super_admin hold it above).
    PERMISSIONS.ADMIN_FEDERATION_VIEW,
    PERMISSIONS.ADMIN_FEDERATION_DELIVER,
  ],

  editor: [
    PERMISSIONS.ADMIN_ACCESS,
    PERMISSIONS.ADMIN_CONTENT_VIEW,
    PERMISSIONS.ADMIN_CONTENT_PUBLISH,
    PERMISSIONS.ADMIN_CONTENT_MEDIA_CREATE,
    PERMISSIONS.ADMIN_CONTENT_MANAGE,
    // P2 reconciliation (TIN-2435): member self-service core floor.
    PERMISSIONS.ADMIN_EVENTS_VIEW,
    PERMISSIONS.ADMIN_ANALYTICS_VIEW,
  ],

  event_manager: [
    PERMISSIONS.ADMIN_ACCESS,
    // P2 reconciliation (TIN-2435): member self-service core floor.
    PERMISSIONS.ADMIN_CONTENT_VIEW,
    PERMISSIONS.ADMIN_CONTENT_PUBLISH,
    PERMISSIONS.ADMIN_EVENTS_VIEW,
    PERMISSIONS.ADMIN_EVENTS_MANAGE,
    PERMISSIONS.ADMIN_ANALYTICS_VIEW,
  ],

  contributor: [
    PERMISSIONS.ADMIN_ACCESS,
    PERMISSIONS.ADMIN_CONTENT_VIEW,
    PERMISSIONS.ADMIN_CONTENT_PUBLISH,
    PERMISSIONS.ADMIN_CONTENT_MEDIA_CREATE,
    // P2 reconciliation (TIN-2435): member self-service core floor.
    PERMISSIONS.ADMIN_EVENTS_VIEW,
  ],

  member: [
    PERMISSIONS.ADMIN_ACCESS,
    PERMISSIONS.ADMIN_CONTENT_VIEW,
    PERMISSIONS.ADMIN_EVENTS_VIEW,
  ],

  viewer: [
    PERMISSIONS.ADMIN_ACCESS,
    PERMISSIONS.ADMIN_ANALYTICS_VIEW,
  ],
};

// MEMBER_SELF_SERVICE_CORE is defined AS the member row, by construction
// (TIN-2435). Every role ranked at or above `member` in ROLE_HIERARCHY
// must hold a superset of this core (invariant P2).
export const MEMBER_SELF_SERVICE_CORE: readonly string[] = Object.freeze([
  ...ROLE_PERMISSIONS.member,
]);

// Feature domains are derived from `admin.<domain>.<verb>` (with
// `admin.access` -> `access`) or `<domain>.own.<verb>`. Do not invent
// new domains; the nine below are the ratified set. The original eight were
// ratified under TIN-2435; `federation` is the ninth domain, deliberately
// amended into the charter by the R2 ratification (TIN-2638, operator-
// ratified 2026-07-07, bundled with the 0.5.0 cut).
export const FEATURE_DOMAINS = [
  'access',
  'users',
  'content',
  'events',
  'analytics',
  'settings',
  'security',
  'logs',
  'federation',
] as const;

export type FeatureDomain = (typeof FEATURE_DOMAINS)[number];

// P3 registry: covers role permissions plus the explicit-only own-scope
// capabilities. Registration does not grant a permission to any role.
export const PERMISSION_FEATURE_DOMAIN: Record<Permission, FeatureDomain> = {
  'admin.access': 'access',
  'admin.users.view': 'users',
  'admin.users.manage': 'users',
  'admin.users.delete': 'users',
  'admin.content.view': 'content',
  'admin.content.publish': 'content',
  'admin.content.media_create': 'content',
  'admin.content.manage': 'content',
  'admin.content.moderate': 'content',
  'admin.content.delete': 'content',
  'admin.events.view': 'events',
  'admin.events.manage': 'events',
  'admin.events.delete': 'events',
  'admin.analytics.view': 'analytics',
  'admin.analytics.export': 'analytics',
  'admin.settings.view': 'settings',
  'admin.settings.manage': 'settings',
  'admin.security.view': 'security',
  'admin.security.manage': 'security',
  'admin.logs.view': 'logs',
  'admin.logs.export': 'logs',
  'admin.federation.view': 'federation',
  'admin.federation.deliver': 'federation',
  'content.own.publish': 'content',
  'federation.own.deliver': 'federation',
};

// Two-axis role charter (operator-ratified 2026-07-04, TIN-2435).
// Axis 1 (governance spine): viewer -> member -> moderator -> admin ->
// super_admin, totally ordered by ROLE_HIERARCHY; governs who manages whom.
// Axis 2 (specialists): editor / event_manager / contributor hold
// feature-scoped capability sets that do NOT nest into the spine order
// (TIN-1606 precedent: event_manager vs contributor non-nesting is
// ratified product policy).
export type RoleAxis = 'governance-spine' | 'specialist';

export interface RoleCharterEntry {
  axis: RoleAxis;
  rank: number;
}

export const ROLE_CHARTER: Record<AdminRole, RoleCharterEntry> = {
  super_admin: { axis: 'governance-spine', rank: ROLE_HIERARCHY.super_admin },
  admin: { axis: 'governance-spine', rank: ROLE_HIERARCHY.admin },
  moderator: { axis: 'governance-spine', rank: ROLE_HIERARCHY.moderator },
  editor: { axis: 'specialist', rank: ROLE_HIERARCHY.editor },
  event_manager: { axis: 'specialist', rank: ROLE_HIERARCHY.event_manager },
  contributor: { axis: 'specialist', rank: ROLE_HIERARCHY.contributor },
  member: { axis: 'governance-spine', rank: ROLE_HIERARCHY.member },
  viewer: { axis: 'governance-spine', rank: ROLE_HIERARCHY.viewer },
};




export type ContentVisibility = 'public' | 'members' | 'admin' | 'private';




export const VALIDATION_RULES = {
  username: {
    pattern: /^[a-zA-Z0-9_-]{3,20}$/,
    minLength: 3,
    maxLength: 20,
    message: 'Username must be 3-20 characters, alphanumeric with _ or -',
  },
  handle: {
    pattern: /^[a-zA-Z0-9_-]{3,20}$/,
    minLength: 3,
    maxLength: 20,
    message: 'Handle must be 3-20 characters, alphanumeric with _ or -',
  },
  password: {
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumber: true,
    requireSpecial: true,
    message: 'Password must be at least 12 characters with uppercase, lowercase, number, and special character',
  },
} as const;
