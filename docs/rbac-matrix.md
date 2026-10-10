# RBAC Matrix

`@tummycrypt/tinyland-auth` has two related but different RBAC concepts:

1. Role management order decides whether one role may grant, invite, update, or
   revoke another role.
2. Permission matrix decides which product capabilities a role has.

The permission matrix is not a strict superset hierarchy. For example,
`event_manager` owns event operations while `contributor` owns content
contribution. Neither role should be inferred to contain every permission from
the other.

## Role Management Order

Role management uses `ROLE_HIERARCHY` as the source of truth:

| Rank | Role | Meaning |
| --- | --- | --- |
| 100 | `super_admin` | System owner; can manage every lower role. |
| 90 | `admin` | General admin; can manage non-owner roles. |
| 70 | `moderator` | Moderation lead; can manage editorial and community roles. |
| 60 | `editor` | Editorial lead; can manage publishing contributors. |
| 50 | `event_manager` | Event lead; can manage contributor/member/viewer roles. |
| 40 | `contributor` | Content contributor; can manage member/viewer roles. |
| 30 | `member` | Authenticated member; can manage viewer under this package order. |
| 10 | `viewer` | Read-only admin surface access; cannot manage roles. |

`canManageRole(actor, target)` returns true only when the actor rank is
strictly greater than the target rank. Equal-rank management is always false.
Hyphenated role names are normalized to underscore names before lookup.

## Capability Matrix

Capability checks use `ROLE_PERMISSIONS`, `hasPermission()`, and the
domain-specific helpers such as `canCreateEvents()` or `canEditPosts()`.

Important rule: do not assert that every higher management role has a strict
permission superset of every lower role. Product roles are allowed to be
capability-specific.

Since TIN-2435 (operator-ratified 2026-07-04) the matrix additionally
guarantees a floor: every role ranked at or above `member` holds
`MEMBER_SELF_SERVICE_CORE` (`admin.access`, `admin.content.view`,
`admin.events.view` -- the `member` row, by construction). See
[role-charter.md](./role-charter.md) for the full two-axis charter and the
P1/P2/P3 invariants.

Since 0.5.0 (operator-ratified 2026-07-07, R1/R2 = TIN-2637/TIN-2638) the
vocabulary includes the `federation` feature domain — the ninth, and the
first domain amended into the charter after TIN-2435 closed the set:

- `admin.federation.view` and `admin.federation.deliver` are held by
  exactly `moderator`, `admin`, and `super_admin` (the governance spine at
  or above `moderator`). No specialist role holds them.
- `canDeliverFederation(role)` is the derived predicate.

Examples:

- `event_manager` has `admin.events.manage`.
- `editor` outranks `event_manager` but does not get event-management
  permission through `ROLE_PERMISSIONS`.
- `contributor` has `admin.content.view`.
- `contributor` does not get event-management permission.
- `admin` outranks `moderator` but does not get `admin.content.moderate`.
- `moderator`, `admin`, and `super_admin` have `admin.federation.deliver`;
  `editor`, `event_manager`, `contributor`, `member`, and `viewer` do not.
- `super_admin` holds every administrative permission. Own-scope permissions
  below remain explicit-only, including for `super_admin`.

## Explicit Own-Scope Permissions

The separately grantable `content.own.publish` and `federation.own.deliver`
capabilities use the existing `AdminUser.permissions[]` carrier. Neither is
included in any `ROLE_PERMISSIONS` row or in `MEMBER_SELF_SERVICE_CORE`;
registration does not grant either capability to a member or administrator.
`EXPLICIT_USER_PERMISSIONS` identifies this explicit-only vocabulary.

- `PERMISSIONS.CONTENT_OWN_PUBLISH` allows publication of the principal's own
  public content when the consuming application's ownership and security
  checks pass.
- `PERMISSIONS.FEDERATION_OWN_DELIVER` allows outbound delivery for the
  principal's own actor/content when those checks and federation policy pass.

Check the current authoritative user with `hasPermission(user, permission)`;
do not infer either grant from a role or a stale session projection. This
permission check alone does not establish ownership, active account state,
completed onboarding/MFA, or consent to public delivery. The application must
enforce those conditions independently. The two grants are independent:
publishing does not imply delivery, and delivery does not imply publishing.

These capabilities grant no cross-user publication, moderation, deletion,
invitation authority, administrative federation access, or role promotion.
Existing role-only helpers such as `canCreatePublicContent(role)` and
`canDeliverFederation(role)` keep their administrative meanings and do not
inspect explicit user grants. Neither permission is accepted implicitly from
an invitation payload; trusted application policy must issue explicit grants.

`Permission` is the complete permission union; `AdminPermission` keeps the
administrative vocabulary and `OwnPermission` names the two own-scope IDs.
Both IDs map to existing `content`/`federation` feature domains, not new domains.

## Downstream Test Guidance

Consumer repos such as `tinyland.dev` should test:

- role-management policy against `ROLE_HIERARCHY`
- permission checks against `ROLE_PERMISSIONS`
- product-specific helper behavior where route policy uses helpers
- explicit capability gaps between peer/specialized roles
- absent/individual/revoked own-scope grants, ownership checks, and unchanged
  administrative authority (including `super_admin`'s explicit-only boundary)

Do not write a property test that assumes `ROLE_PERMISSIONS[higher]` is a
superset of `ROLE_PERMISSIONS[lower]`. That property is false by design.
