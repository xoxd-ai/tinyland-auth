# Role Charter — the two-axis RBAC model

Operator-ratified 2026-07-04 (TIN-2435 comment thread). This page is the
narrative companion to the machine-readable charter shipped in
`src/types/permissions.ts` (`ROLE_CHARTER`, `PERMISSION_FEATURE_DOMAIN`,
`MEMBER_SELF_SERVICE_CORE`).

## The two axes

`@tummycrypt/tinyland-auth` roles live on two independent axes:

1. **Governance rank** — a total order over who may manage (grant, invite,
   update, revoke) whom. Source of truth: `ROLE_HIERARCHY`. The governance
   spine is `viewer → member → moderator → admin → super_admin`.
2. **Feature capability** — what a role may do, expressed as permission
   strings in `ROLE_PERMISSIONS`, each tagged with a feature domain in
   `PERMISSION_FEATURE_DOMAIN`. Capability is horizontal:
   `editor`, `event_manager`, and `contributor` are **specialists** whose
   capability sets serve a feature domain, not a rung of the governance
   ladder.

`ROLE_CHARTER` tags every role with its axis (`governance-spine` |
`specialist`) and its `ROLE_HIERARCHY` rank.

## The lattice statement

`ROLE_PERMISSIONS` is an **intentional lattice**, not a rank-monotone
hierarchy. A role with a higher governance rank is NOT required to hold a
superset of a lower role's permissions. Pinned counterexamples (see
`tests/rbac-invariants.test.ts`):

- `editor` (rank 60) does not hold `admin.events.manage`, which
  `event_manager` (rank 50) holds.
- `admin` (rank 90) does not hold `admin.content.moderate`, which
  `moderator` (rank 70) holds.
- `member` (rank 30) does not hold `admin.analytics.view`, which `viewer`
  (rank 10) holds.

Precedent: TIN-1606 (decision-of-record, 2026-05-25) ratified
`event_manager`/`contributor` non-nesting as product policy. TIN-2435
generalizes it: specialist capabilities never flow up the governance spine
implicitly. Do not write tests asserting rank-superset monotonicity — the
property is false by design (`super_admin` is the only role guaranteed to
hold every administrative permission; explicit-only own-scope grants are
separate).

## Invariants P1 / P2 / P3

The three ratified invariants, enforced deterministically and exhaustively
in `tests/rbac-invariants.test.ts`:

- **P1 — management order.** For every ordered role pair `(a, b)`:
  `canManageRole(a, b) === ROLE_HIERARCHY[a] > ROLE_HIERARCHY[b]`. No other
  surface (arrays, UI tables, route guards) may define management order.
- **P2 — member self-service floor.** `MEMBER_SELF_SERVICE_CORE` is defined
  as `ROLE_PERMISSIONS.member` by construction (`admin.access`,
  `admin.content.view`, `admin.events.view`). Every role ranked at or above
  `member` holds a superset of the core: reaching any higher role never
  costs a user their member self-service capabilities.
- **P3 — registry guard.** `PERMISSION_FEATURE_DOMAIN` covers the complete
  permission vocabulary. Role-granted permissions and
  `EXPLICIT_USER_PERMISSIONS` form disjoint, exhaustive sets; registering an
  explicit-only permission does not grant it to any role. Domains are derived
  from `admin.<domain>.<verb>` (`admin.access` → `access`) or
  `<domain>.own.<verb>`; the ratified domain set is `access`,
  `users`, `content`, `events`, `analytics`, `settings`, `security`,
  `logs`, `federation`. Do not invent domains — `federation` (the ninth)
  was a deliberate charter amendment, operator-ratified 2026-07-07
  (R2, TIN-2638, bundled with the 0.5.0 cut); any further domain requires
  the same ratification path.

## Federation domain (0.5.0 — R1/R2, TIN-2637 / TIN-2638)

Operator-ratified 2026-07-07:

- **R2 (TIN-2638)** amends the charter with `federation` as the ninth
  feature domain, carrying `admin.federation.view` (read side) and
  `admin.federation.deliver` (outbound delivery authority).
- **R1 (TIN-2637)** grants `admin.federation.deliver` (and `.view`) to
  `moderator`; `admin` and `super_admin` inherit/hold it per the grant.
  Delivery is a **governance-spine capability** anchored at `moderator` —
  the fedi/community moderation role — and held by every spine role ranked
  at or above it. No specialist (`editor`, `event_manager`, `contributor`)
  and no role below `moderator` (`member`, `viewer`) holds it: the lattice
  is explicit-array (grants do not flow up by rank), so `admin` holds the
  grant explicitly and `super_admin` holds it via the full admin-vocabulary row.
- Predicate: `canDeliverFederation(role)` derives from `ROLE_PERMISSIONS`
  via the SSOT helper, like every other `can*` predicate.
- Semantics are intentionally limited to `view`/`deliver`; consumer wiring
  (e.g. pulse delivery workers) is a separate lane (C4).

## Explicit own-scope amendment (2026-09-19)

`content.own.publish` and `federation.own.deliver` are explicit user capabilities
in the existing `content` and `federation` domains, not new roles or default
member grants. They use `AdminUser.permissions[]` and remain explicit-only
even for `super_admin`. This amends P3's original role-only registry coverage;
the governance order, member floor, and administrative capability matrix stay
unchanged.

The user-aware `hasPermission()` family recognizes each grant independently.
It does not grant administrative publication/delivery or cross-user authority.
Consumers still enforce current-principal security state, resource ownership,
and public-delivery policy. Role-only `can*` helpers remain unchanged. See
[the explicit own-scope contract](./rbac-matrix.md#explicit-own-scope-permissions).

## Role × feature charter (ratified)

Operator-ratified 2026-07-04, TIN-2435:

| Role | Axis | Charter |
| --- | --- | --- |
| `super_admin` | governance-spine | System owner; holds every administrative permission; sole default holder of destructive/exporting grants (`users.delete`, `analytics.export`, `settings.manage`, `security.*`, `logs.export`). Own-scope capabilities require explicit grants. |
| `admin` | governance-spine | General administration across domains: user management, content/events lifecycle including deletion, settings and logs view, federation view/deliver (0.5.0, TIN-2637). |
| `moderator` | governance-spine | **Fedi / community moderation**: `content.moderate`, `users.view`, `logs.view`, `federation.view`/`federation.deliver` (0.5.0, TIN-2637), plus public publishing and the member core. |
| `editor` | specialist | **Blog editorial**: `content.manage`, `content.publish`, `content.media_create`, analytics view, plus the member core. |
| `event_manager` | specialist | **Events / calendaring**: `events.manage`, public publishing, analytics view, plus the member core. |
| `contributor` | specialist | **Drafts / submissions**: authors content including media (`content.media_create`) and public-visibility posts (`content.publish`), plus the member core. No manage/moderate/delete grants. |
| `member` | governance-spine | **Self-service core**: `admin.access`, `admin.content.view`, `admin.events.view` — own-content and own-event self-service; members/private-visibility authoring by default. Own public publication/delivery require explicit grants. |
| `viewer` | governance-spine | Read-only admin surface: `admin.access`, `admin.analytics.view`. Below the member floor; holds no self-service authoring capability. |

## Predicate derivation

Every `can*` predicate in `src/core/permissions/index.ts` derives from
`ROLE_PERMISSIONS` — the hand-maintained role arrays (the tinyland.dev#628
anti-pattern class: TIN-2429, TIN-2435) are gone. Notable derivations:

- Domain list views (`canViewPosts`, `canViewEvents`, `canViewProfiles`,
  `canViewVideos`, `canEditOwnProfile`) floor at `admin.access`,
  preserving the historical "every valid role sees the admin list views"
  behavior.
- Own-content self-service (`canCreatePosts`, `canCreateMemberOnlyContent`,
  `canEditOwnContent`, `canDeleteOwnContent`, `canViewMemberOnlyContent`)
  derives from `admin.content.view`; own-event creation
  (`canCreateEvents`) derives from `admin.events.view` — the member core
  markers.
- Manage/delete tiers derive from `content.manage`, `content.moderate`,
  `content.delete`, `events.manage`, `events.delete`, `users.*`,
  `content.publish`, `content.media_create`.

The full role × predicate matrix is locked cell-by-cell in
`tests/rbac-invariants.test.ts`.

## Consumer context (ratified direction)

- **Userspace is being turned on.** The `tinyland.dev` member self-service
  subtree (`/admin/member/*`) will be activated for `member`-and-above in a
  separate app-side lane; the P2 floor exists so that activation is safe
  for every role at or above `member`.
- **The admin UI floor will derive from these predicates.** The app's
  hardcoded role-array floor is being replaced with `ROLE_PERMISSIONS`
  -derived predicates — the same SSOT the API layer uses — making this
  package's matrix, charter, and invariants the live gating truth.
