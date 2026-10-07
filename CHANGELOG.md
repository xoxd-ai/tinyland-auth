# @tummycrypt/tinyland-auth

## 1.0.0

### Major Changes

- **BREAKING (RS6, TIN-5766): the production entry has no TOTP bypass, no
  caller-injected TOTP verifier and no public test-seam option.** Migration: [docs/migration-1.0.md](docs/migration-1.0.md).

  Removed (breaking):

  1. `TOTPServiceConfig.devMode` (exported from `.` and `./totp`).
  2. `TOTPServiceConfig.testCode` (exported from `.` and `./totp`).
  3. The fixed-code shortcut in `TOTPService.verifyToken` and
     `verifyTokenWithStep`, and the private `devMode` / `testCode` fields.
  4. `createTOTPService` no longer passes `devMode`.
  5. `TOTPConfig.devMode` (`.` and `./types`) and
     `DEFAULT_AUTH_CONFIG.totp.devMode`. Without the bypass the setting did
     nothing.
  6. The unreleased seams from the 1.0 development line (never published):
     `TOTPServiceConfig.verifier`, `TotpVerifier`, `otplibTotpVerifier`,
     `Clock`, `systemClock`, `BackupCodeGenerator`, and the `clock` /
     `generateBackupCodes` options on `TOTPServiceConfig`,
     `SessionManagerConfig` and `BootstrapServiceConfig`.

  7. The mTLS development auto-pass (RP2). `requireMTLS`,
     `extractCertificateFromEvent` and `getCertificateFingerprintFromEvent`
     (`./sveltekit`) no longer admit a request without a client certificate
     when `NODE_ENV` is unset or `development`, or when the request host is
     `localhost`, `127.0.0.1` or `*.local`. Under adapter-node without
     `ORIGIN` that host comes from the client's `Host` header, so 0.7.x
     admitted any request that sent `Host: localhost`, and every request when
     `NODE_ENV` was unset. `MTLSOptions.isDevelopment` (`.` and
     `./validation`) and the `dev-mode-no-cert` certificate are gone:
     `extractCertificate` and `getCertificateFingerprint` always read the
     forwarded certificate headers. `requireMTLS` takes an optional
     `MTLSOptions` (`validFingerprints`).
  8. `AuthConfig.isDevelopment` and `DEFAULT_AUTH_CONFIG.isDevelopment`. No
     code read it.
  9. `BootstrapServiceConfig.verifyTOTP` and
     `BootstrapServiceConfig.generateTOTPSecret` (RP2). In 0.7.x
     `complete()` trusted the caller's verifier alone, so
     `verifyTOTP: () => true` created the first `super_admin` with any code.
     `initiate()` now generates the secret from the CSPRNG and `complete()`
     verifies the code itself with otplib (same step, window and digits as
     `TOTPService`). It rejects non-numeric codes and malformed or
     below-floor secrets, and refuses once any user exists, so a replayed
     state, or a second state completed after the first admin exists, cannot
     add another `super_admin`. The check is not atomic against two racing
     completes.

  A legacy `devMode` / `testCode` / `isDevelopment` / `verifyTOTP` /
  `generateTOTPSecret` key passed at runtime is ignored. It never accepts a
  fixed code, pins a secret or skips a certificate check.

- **Test harness behind a hard gate (RS5).** `src/testing` holds
  `createTestAdmissionIssuer`, `generateTestIdentity`, `createManualClock`,
  `createDeterministicBackupCodeGenerator` and the
  `createTestTOTPService` / `createTestSessionManager` /
  `createTestBootstrapService` seam factories. It is excluded from the
  production build, `//:pkg` and the npm tarball. It is not exported. It
  throws on load unless `process.env.NODE_ENV === 'test'`, so it fails closed
  when `NODE_ENV` is unset. It never reads a caller-supplied environment:
  `TestAdmissionIssuerConfig.env` and the `env` parameters of the gate
  functions are gone. Admission also requires
  `TINYLAND_AUTH_TEST_ADMISSION=enabled`.

- **Production-exclusion proof.** `scripts/check-production-artifact.mjs`
  checks a built package and a production Vite bundle of every public entry
  for testing symbols, the unique testing sentinel, removed bypass names
  (including `isDevelopment`, `detectDevelopment`, `dev-mode-no-cert` and
  `verifyTOTP`) and
  the internal seam writer, and confirms that `./testing` does not resolve. It
  runs on the `pnpm pack` tarball (`pnpm check:production-artifact`, in CI) and
  on Bazel `//:pkg` (`//:production_artifact_test`).
  `tests/production-artifact.test.ts` proves the check catches injected leaks.

### Patch Changes

- `build` removes `dist/` before compiling, and `prepublishOnly` also runs
  `check:production-artifact`, so a manual publish from a tree with a stale
  `dist/` cannot ship it.
- Docs: the mTLS helpers trust the forwarded certificate headers. Without
  `validFingerprints`, a forwarded subject with the verify header absent or
  `NONE` is admitted, so the edge proxy must strip client-supplied copies.
  This is unchanged from 0.7.x and is now stated on `MTLSOptions`,
  `requireMTLS` and in the README.

- `fix(sveltekit)`: `DEFAULT_COOKIE_CONFIG.secure` is now `true` unless
  `NODE_ENV` is exactly `development` or `test`. 0.7.x set it only when
  `NODE_ENV` was `production`, so session cookies lost `Secure` when
  `NODE_ENV` was unset.
- `fix(security)`: `generateSecurePassword` imports `randomInt` from `crypto`
  instead of calling CommonJS `require` inside ESM, which threw
  `ReferenceError` in plain Node. It also no longer has modulo bias.
- The internal seam writer (`dist/core/seams`, not exported) refuses unless
  `NODE_ENV` is exactly `test`, so a file-URL import cannot install a clock
  in production.
- `fix(totp)`: `base32ByteLength` counts padding with a linear scan instead of
  a backtracking regex (CodeQL `js/polynomial-redos`). The 128-bit floor is
  unchanged for well-formed secrets.

## 0.7.1

### Patch Changes

- `build` removes `dist/` before compiling, and `prepublishOnly` also runs
  `check:production-artifact`, so a manual publish from a tree with a stale
  `dist/` cannot ship it.
- Docs: the mTLS helpers trust the forwarded certificate headers. Without
  `validFingerprints`, a forwarded subject with the verify header absent or
  `NONE` is admitted, so the edge proxy must strip client-supplied copies.
  This is unchanged from 0.7.x and is now stated on `MTLSOptions`,
  `requireMTLS` and in the README.

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

- `build` removes `dist/` before compiling, and `prepublishOnly` also runs
  `check:production-artifact`, so a manual publish from a tree with a stale
  `dist/` cannot ship it.
- Docs: the mTLS helpers trust the forwarded certificate headers. Without
  `validFingerprints`, a forwarded subject with the verify header absent or
  `NONE` is admitted, so the edge proxy must strip client-supplied copies.
  This is unchanged from 0.7.x and is now stated on `MTLSOptions`,
  `requireMTLS` and in the README.

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

- `build` removes `dist/` before compiling, and `prepublishOnly` also runs
  `check:production-artifact`, so a manual publish from a tree with a stale
  `dist/` cannot ship it.
- Docs: the mTLS helpers trust the forwarded certificate headers. Without
  `validFingerprints`, a forwarded subject with the verify header absent or
  `NONE` is admitted, so the edge proxy must strip client-supplied copies.
  This is unchanged from 0.7.x and is now stated on `MTLSOptions`,
  `requireMTLS` and in the README.

- Clarify the package release authority: the TypeScript import API remains
  `@tummycrypt/tinyland-auth`, npmjs publication is disabled, GitHub Packages
  uses the `@tinyland-inc/tinyland-auth` mirror coordinate, and Bazel targets
  provide the package proof lane.

## 0.3.3

### Patch Changes

- `build` removes `dist/` before compiling, and `prepublishOnly` also runs
  `check:production-artifact`, so a manual publish from a tree with a stale
  `dist/` cannot ship it.
- Docs: the mTLS helpers trust the forwarded certificate headers. Without
  `validFingerprints`, a forwarded subject with the verify header absent or
  `NONE` is admitted, so the edge proxy must strip client-supplied copies.
  This is unchanged from 0.7.x and is now stated on `MTLSOptions`,
  `requireMTLS` and in the README.

- Make TOTP and invitation exports compatible with both legacy `otplib` v12
  authenticator exports and modern `otplib` v13 functional exports used by
  SvelteKit SSR consumers.

## 0.3.2

### Patch Changes

- `build` removes `dist/` before compiling, and `prepublishOnly` also runs
  `check:production-artifact`, so a manual publish from a tree with a stale
  `dist/` cannot ship it.
- Docs: the mTLS helpers trust the forwarded certificate headers. Without
  `validFingerprints`, a forwarded subject with the verify header absent or
  `NONE` is admitted, so the edge proxy must strip client-supplied copies.
  This is unchanged from 0.7.x and is now stated on `MTLSOptions`,
  `requireMTLS` and in the README.

- Disable package-level npm provenance so the self-hosted Bazel package publish
  lane can publish without npm rejecting the runner environment.

## 0.3.1

### Patch Changes

- `build` removes `dist/` before compiling, and `prepublishOnly` also runs
  `check:production-artifact`, so a manual publish from a tree with a stale
  `dist/` cannot ship it.
- Docs: the mTLS helpers trust the forwarded certificate headers. Without
  `validFingerprints`, a forwarded subject with the verify header absent or
  `NONE` is admitted, so the edge proxy must strip client-supplied copies.
  This is unchanged from 0.7.x and is now stated on `MTLSOptions`,
  `requireMTLS` and in the README.

- Fix Node ESM consumption of the TOTP and invitation exports by importing the
  CommonJS `otplib` package through its default namespace.

## 0.2.2

### Patch Changes

- `build` removes `dist/` before compiling, and `prepublishOnly` also runs
  `check:production-artifact`, so a manual publish from a tree with a stale
  `dist/` cannot ship it.
- Docs: the mTLS helpers trust the forwarded certificate headers. Without
  `validFingerprints`, a forwarded subject with the verify header absent or
  `NONE` is admitted, so the edge proxy must strip client-supplied copies.
  This is unchanged from 0.7.x and is now stated on `MTLSOptions`,
  `requireMTLS` and in the README.

- Roll forward published package versions so the next release re-establishes npm artifact truth for the current repo contents. This excludes `@tummycrypt/tinyland-schemas` because `0.2.1` is not published on npm yet.

## 0.2.1

### Patch Changes

- `build` removes `dist/` before compiling, and `prepublishOnly` also runs
  `check:production-artifact`, so a manual publish from a tree with a stale
  `dist/` cannot ship it.
- Docs: the mTLS helpers trust the forwarded certificate headers. Without
  `validFingerprints`, a forwarded subject with the verify header absent or
  `NONE` is admitted, so the edge proxy must strip client-supplied copies.
  This is unchanged from 0.7.x and is now stated on `MTLSOptions`,
  `requireMTLS` and in the README.

- 429a49c: Strip .js.map sourcemaps from published packages and resolve workspace:\* dependencies to real version ranges.
