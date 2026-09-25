# @tummycrypt/tinyland-auth

## Unreleased

### Major Changes

- Add a tenant-scoped atomic first-user bootstrap storage contract for memory,
  file, fixed-tenant, and external adapters. Inert claims carry no authority;
  exact finalization replay is idempotent, mismatched replay conflicts, and an
  immutable receipt remains separate from mutable user/TOTP/backup-code state.
  Canonical claim/finalization/receipt helpers and a framework-neutral storage
  conformance runner define the future durable-adapter contract. The built-in
  memory and file adapters implement this unreleased source contract;
  `createFixedTenantStorageAdapter` can only forward it to a backend that has
  a native implementation. The current PostgreSQL and Redis adapters do not
  implement it and are unsupported for atomic first-user bootstrap.
- Reject unknown, missing, non-canonical, sparse, and non-JSON bootstrap
  claim/finalization material before authority writes or replay comparison.
  Canonical replay encoding rejects `-0`, non-finite numbers, `undefined`,
  functions, symbols, and bigint values instead of collapsing them.
- Bind file records to their normalized tenant filename and replace automatic
  PID-based lock takeover with a bounded, constant-space two-slot protocol.
  Release stages and publishes hard links to a privately held owner inode, then
  performs no pathname read or delete; the next owner compacts only the prior
  released slot. Retry waits are
  deadline-clamped, ordinary contention is retryable, and only ambiguous
  ownership state requires attended recovery.
- Harden user deletion so bootstrap actors cannot be removed and ordinary file
  users are disabled and have sessions revoked before destructive writes.
- Reconcile persisted 0.7 file stores without bootstrap receipts when exactly
  one active, unlocked `super_admin` identifies legacy ownership. The adapter
  atomically records that immutable migration marker before allowing ordinary
  user creation; missing or ambiguous ownership remains fail-closed.
- Replace `BootstrapService`'s credential-bearing browser state and composed
  writes with an opaque attempt reference, explicit server-side attempt
  custody, finalized-metadata/decryptability status, encrypted-factor
  round-trip validation, and the atomic storage finalization protocol. Attempt
  custody now expires prepared state, rejects stale profile snapshots with a
  digest CAS, enforces the exact ten-minute claim lifetime without expiry skew,
  and never
  re-discloses pending credentials from receipt replay. A framework-neutral
  attempt-store conformance runner makes those CAS rules reusable. Session
  identity is immutable so an active claim cannot be bypassed by rebinding an
  old session. Claim acceptance now revokes every pre-bootstrap session and
  blocks new sessions until finalization; role and permission guards require a
  matching storage-loaded user instead of trusting an embedded session role.
  TOTP verification accepts synchronous or asynchronous verifiers, awaits the
  result, and requires the exact value `true`; verifier rejection fails closed.
  A delayed exact `complete()` racing a winner re-reads the immutable receipt
  after asynchronous verification/encryption and replays the committed success
  even when the winner already deleted attempt custody.
  Downstream initiation remains operator-only and must be protected by a local
  or private administrative gate.
  This is a breaking, source-only 0.8 contract. It does not claim a 0.8
  release, registry promotion, PostgreSQL/Redis support, or consumer adoption.

## 0.7.1

### Patch Changes

- Restore the Bazel module's shared `rules_ts` extension request to TypeScript
  5.9.3. Version 0.7.0 requested 6.0.3 from a non-root module, which conflicts
  with the rest of the first-party Bazel graph before a consumer can select its
  own toolchain. The package still typechecks directly with TypeScript 6.0.3;
  Bazel additionally proves source compatibility with the coordinated 5.9.3
  toolchain until the graph migrates as one change.

## 0.7.0

### Major Changes

- **BREAKING (TIN-2780): `InvitationService` is no longer exported.** The package
  public surface previously re-exported a local `InvitationService` /
  `createInvitationService` whose `createInvitation` performed **zero role
  authorization** — the caller's requested `role` flowed straight into the minted
  invite. A fresh consumer reaching for it got an ungated, fail-open duplicate.

  The authoritative, **fail-closed** invite flow is the standalone
  [`@tummycrypt/tinyland-invitation`](https://github.com/tinyland-inc/tinyland-invitation)
  package, ratified as the single invitation role-authority under **TIN-1607**
  (consolidation decision: tinyland.dev PR #649). Its default enforces the real
  role hierarchy (mirrors `canManageRole`) and `createInvitation` throws
  `InvitationError` when the actor may not mint the target role.

  **Migration:** replace any
  `import { InvitationService, createInvitationService } from '@tummycrypt/tinyland-auth'`
  with the standalone package and thread `createdByRole`. The removed symbols
  (`InvitationService`, `createInvitationService`, `InvitationServiceConfig`,
  `CreateInvitationOptions`, `CreateInvitationResult`) are no longer reachable —
  the package `exports` map exposes no `./invitation` subpath. RBAC helpers
  (`canManageRole`, `canInviteForRole`) and the `InvitationStorage` interface are
  unaffected.

### Patch Changes

- Migrate the TOTP compatibility layer to otplib v13's stateless functional
  API while preserving the configured verification window and exact time-step
  delta used by replay protection. Fresh secrets retain a 160-bit floor,
  legacy sub-128-bit secrets fail closed with an explicit re-enrollment error,
  and the unknown-user timing path uses a valid dummy secret.
- Refresh bcryptjs, its type definitions, TypeScript, and Node type tooling.
- Align the Bazel TypeScript toolchain with the pnpm lock and add a standing
  release-metadata guard over package, module, package-rule, changelog, and tag
  versions.

## 0.6.0

### Minor Changes

- TOTP replay protection. `TOTPService.verifyTokenWithStep()` is a new,
  replay-resistant verification surface: it derives the absolute time-step a
  submitted code was minted for and rejects any step `<=` a caller-supplied
  `lastUsedStep`, so a valid code can no longer be reused inside its
  `+/-window` validity window (~90s at window=1). It returns the consumed step
  for callers to persist. `EncryptedTOTPSecret` gains an optional
  `lastUsedTotpStep` field to hold that marker. The legacy `verifyToken()`
  boolean surface is unchanged (stateless, opt-in migration).

## 0.5.0

### Minor Changes

- Federation lattice (C3; R1/R2 = TIN-2637/TIN-2638, operator-ratified
  2026-07-07). A deliberate charter amendment: TIN-2435 closed the feature
  domain set at eight; R2 ratifies `federation` as the ninth domain,
  bundled with this cut.

  **New feature domain**: `federation` added to `FEATURE_DOMAINS` (the
  ratified set is now nine domains).

  **New permission strings** (both mapped to the `federation` domain in
  `PERMISSION_FEATURE_DOMAIN`):

  - `admin.federation.view` → moderator, admin, super_admin
  - `admin.federation.deliver` → moderator, admin, super_admin (R1:
    granted to moderator; admin and super_admin inherit/hold — the lattice
    is explicit-array, so admin holds the grant explicitly and super_admin
    holds it via the full-vocabulary row)

  Delivery is a governance-spine capability anchored at `moderator` (the
  fedi/community moderation role). No specialist role (`editor`,
  `event_manager`, `contributor`) and no role below `moderator` holds it.

  **New export**: `canDeliverFederation(role)`, derived from
  `ROLE_PERMISSIONS` via the SSOT helper like every other `can*` predicate.

  **Invariants**: P1 (management order) and P2 (member self-service floor)
  unchanged; P3 registry closure extended over the two new strings. The
  rbac-invariants suite exhaustively locks the federation holder set to
  exactly {moderator, admin, super_admin}.

  Consumer wiring (pulse delivery workers etc.) is out of scope for this
  package (C4, separate lane).

## 0.4.0

### Minor Changes

- RBAC SSOT hardening (TIN-2435, operator-ratified 2026-07-04; precedent
  TIN-1606).

  **New exports**: `MEMBER_SELF_SERVICE_CORE` (defined as
  `ROLE_PERMISSIONS.member` by construction: `admin.access`,
  `admin.content.view`, `admin.events.view`), `ROLE_CHARTER` (two-axis
  role tags: governance-spine | specialist, with `ROLE_HIERARCHY` ranks),
  `FEATURE_DOMAINS` and `PERMISSION_FEATURE_DOMAIN` (feature-domain
  registry over the permission vocabulary), plus types `FeatureDomain`,
  `RoleAxis`, `RoleCharterEntry`.

  **P2 data reconciliation** (behavior change: view-level grants). Every
  role ranked at or above `member` now holds the member self-service core:

  - `moderator` gains `admin.events.view`
  - `editor` gains `admin.events.view`
  - `contributor` gains `admin.events.view`
  - `event_manager` gains `admin.content.view`

  **New permission strings** (behavior change: vocabulary additions so
  `can*` predicates derive from `ROLE_PERMISSIONS` instead of the
  hand-maintained role arrays — the tinyland.dev#628 anti-pattern class):

  - `admin.content.publish` → contributor, event_manager, editor,
    moderator, admin, super_admin (backs `canCreatePublicContent`)
  - `admin.content.media_create` → contributor, editor, admin,
    super_admin (backs `canCreateVideos`)
  - `admin.content.delete` → admin, super_admin (backs `canDeletePosts`,
    `canDeleteVideos`, `canDeleteContent`)
  - `admin.events.delete` → admin, super_admin (backs `canDeleteEvents`)

  **Predicate derivation**: every `can*` predicate now derives from
  `ROLE_PERMISSIONS`. The full role × predicate matrix is locked in
  `tests/rbac-invariants.test.ts`. Intentional behavior deltas (P2
  member-core flow-through; everything else is cell-identical):

  - `canCreateEvents` now true for `moderator`, `editor`, `contributor`
  - `canDeleteOwnContent` now true for `moderator`

  **Invariants**: deterministic, exhaustive tests for P1 (management order
  is `ROLE_HIERARCHY`, all 64 pairs), P2 (member self-service floor), P3
  (feature-domain registry covers the granted vocabulary exactly), plus
  pinned lattice counterexamples documenting that chain-monotonicity is
  NOT an invariant (ratified: TIN-1606, TIN-2435). Docs:
  `docs/role-charter.md`.

### Patch Changes

- Clarify the package release authority: the TypeScript import API remains
  `@tummycrypt/tinyland-auth`, npmjs publication is disabled, GitHub Packages
  uses the `@tinyland-inc/tinyland-auth` mirror coordinate, and Bazel targets
  provide the package proof lane.

## 0.3.3

### Patch Changes

- Make TOTP and invitation exports compatible with both legacy `otplib` v12
  authenticator exports and modern `otplib` v13 functional exports used by
  SvelteKit SSR consumers.

## 0.3.2

### Patch Changes

- Disable package-level npm provenance so the self-hosted Bazel package publish
  lane can publish without npm rejecting the runner environment.

## 0.3.1

### Patch Changes

- Fix Node ESM consumption of the TOTP and invitation exports by importing the
  CommonJS `otplib` package through its default namespace.

## 0.2.2

### Patch Changes

- Roll forward published package versions so the next release re-establishes npm artifact truth for the current repo contents. This excludes `@tummycrypt/tinyland-schemas` because `0.2.1` is not published on npm yet.

## 0.2.1

### Patch Changes

- 429a49c: Strip .js.map sourcemaps from published packages and resolve workspace:\* dependencies to real version ranges.
