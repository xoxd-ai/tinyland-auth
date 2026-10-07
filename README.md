# @tummycrypt/tinyland-auth

Production-grade authentication system with TOTP, RBAC, and pluggable storage.

## Consumption And Release Authority

The TypeScript import API stays under `@tummycrypt/tinyland-auth`. Tinyland's
current release authority for this repo is Bazel-first:

- CI validates the package through a repo-owned GloriousFlywheel runner lane and
  `//:pkg //:test //:typecheck`.
- npmjs publication is disabled in package workflows.
- GitHub Packages mirror publication uses `@tinyland-inc/tinyland-auth`, because
  GitHub Packages npm scopes are owner-bound.
- Bazel consumers should depend through the Tinyland Bazel registry / BCR module
  path instead of relying on a workspace-local package copy.

`pnpm add @tummycrypt/tinyland-auth` is valid only when the consumer is
configured for a registry that intentionally serves the `@tummycrypt` package
scope. It is not the current Tinyland publication authority for this repo.

## Exports

- `.` — core auth: session management, password hashing, permissions, RBAC
- `./sveltekit` — SvelteKit integration: hooks, guards, CSRF, session cookies
- `./storage` — storage adapter interface + memory/file implementations
- `./types` — TypeScript type definitions
- `./totp` — TOTP generation and verification
- `./activity` — activity tracking
- `./audit` — audit logging
- `./cred-gen` — credential generation and display
- `./validation` — input validation utilities

## Invitation Authority

`@tummycrypt/tinyland-auth` does not export an invitation service or factory.
Use `@tummycrypt/tinyland-invitation` version `>=0.2.5` for fail-closed
invitation authorization, minting, acceptance, revocation, and lifecycle
management, composed with the downstream application that owns user creation.

The type-only `AdminInvitation`, `InvitationConfig`, `InvitationStorage`, and
invitation request/response DTO exports remain intentionally available, as do
the invitation-record methods on the built-in storage adapters. These are
compatibility surfaces for persisted data; they neither generate tokens nor
authorize minting, acceptance, roles, or user creation.

The invitation `0.2.5` release has a per-token acceptance lock, but that
lock is process-local. It serializes acceptance only within one Node.js process
and is not a distributed or cross-replica compare-and-set. Consumers sharing
invitation storage across processes or replicas still need a storage-backed CAS
before claiming exactly-once acceptance.

## Storage Adapters

Implement `IStorageAdapter` for your backend:

- **Built-in**: `MemoryStorageAdapter`, `FileStorageAdapter`
- **Separate packages**: `@tummycrypt/tinyland-auth-pg` (PostgreSQL), `@tummycrypt/tinyland-auth-redis` (Upstash Redis)

## Tinyland Databaseless MVP

Tinyland's intended app shape is handle-first and email-less by default:

- directory actors are keyed by handle
- email is optional contact metadata, not identity authority
- sessions bind capabilities to directory actors
- FingerprintJS and Tempo are evidence/overlay planes, not auth credentials
- GitHub OAuth is an app-local provider handoff that creates a normal package
  session after provider policy passes

"Databaseless" describes the storage model (no external database dependency),
not a scale-out guarantee. The built-in `FileStorageAdapter` capability plane
is **single-replica dbless**: safe for the single-replica deployments this
package ships against today, but concurrent multi-replica writers need a
storage-layer compare-and-swap that `IStorageAdapter` does not currently
require or provide. Consumers running more than one replica need a
CAS-capable adapter (e.g. a Postgres/Redis-backed `IStorageAdapter`) or must
stay pinned to a single replica. The `ha.tinyland.dev/*` exception recorded on
the mothership's staging manifests is the current, honest SSOT statement of
that constraint in production — it documents the single-replica posture, it
does not relax it.

See the
[Tinyland databaseless auth MVP](https://github.com/tinyland-inc/tinyland-auth/blob/main/docs/tinyland-databaseless-auth-mvp.md)
and the
[executable example](https://github.com/tinyland-inc/tinyland-auth/blob/main/examples/tinyland-databaseless-auth-mvp.ts).

### Browser fingerprint (anomaly-evidence signal, not an auth factor)

> Fingerprint evidence (operator-canonized 2026-07-05, reworded 2026-07-11 to
> retire the "factor" framing): the Tempo-derived browser fingerprint
> (tinyland-fingerprint — UA-parse + Tempo evidence, NOT the fingerprintjs
> library) is an anomaly-evidence signal, not an enforced authentication
> factor at any layer. It is recorded, not vetoed, by design — a mismatch is
> logged and emitted as discarded OTLP evidence, and it never gates,
> destroys, or is required to establish a session (see the consuming app's
> `fingerprintValidationHandle`, e.g. tinyland.dev `src/hooks.server.ts`
> ~L926-944). Boundary invariant (TIN-1610, ratified): the print is evidence
> at the credential boundary only — `validateSession()` never destroys an
> authenticated session on a missing/changed fingerprint. Do not describe
> this mechanism as "browser-as-a-factor" in product docs; it supplies
> anomaly-detection evidence and a best-effort persistence hint, not a
> credential.

Cross-references: TIN-1610 (evidence-not-veto boundary invariant),
[`@tummycrypt/tinyland-fingerprint` v0.3.0](https://github.com/tinyland-inc/tinyland-fingerprint)
(supplier of the print + Tempo evidence), and prompts-enqueue
golden-objectives §tinyland-auth (corrected 2026-07-05).

## RBAC

Role management order and permission checks are intentionally separate. See
[the RBAC matrix](https://github.com/tinyland-inc/tinyland-auth/blob/main/docs/rbac-matrix.md)
for the package-owned matrix and downstream test guidance, and
[the role charter](https://github.com/tinyland-inc/tinyland-auth/blob/main/docs/role-charter.md)
for the two-axis model and the P1/P2/P3 invariants.

### Role x feature charter (operator-ratified 2026-07-04, TIN-2435)

Roles live on two axes: a **governance spine** (`viewer -> member ->
moderator -> admin -> super_admin`, totally ordered by `ROLE_HIERARCHY`,
governs who manages whom) and horizontal **feature capability**
(`ROLE_PERMISSIONS`, an intentional lattice -- capabilities do NOT nest by
rank; TIN-1606 precedent).

| Role | Axis | Feature charter |
| --- | --- | --- |
| `super_admin` | governance-spine | System owner; every permission. |
| `admin` | governance-spine | General administration across domains. |
| `moderator` | governance-spine | Fedi / community moderation. |
| `editor` | specialist | Blog editorial. |
| `event_manager` | specialist | Events / calendaring. |
| `contributor` | specialist | Drafts / submissions. |
| `member` | governance-spine | Self-service core (`MEMBER_SELF_SERVICE_CORE`). |
| `viewer` | governance-spine | Read-only admin surface. |

Every role at or above `member` holds `MEMBER_SELF_SERVICE_CORE`
(invariant P2), and every `can*` predicate derives from `ROLE_PERMISSIONS`
-- there are no hand-maintained role arrays. Machine-readable charter:
`ROLE_CHARTER` and `PERMISSION_FEATURE_DOMAIN` in
`src/types/permissions.ts`.

## Test harness (not published)

Since 1.0.0 (rulings RS5 and RS6, TIN-5766) the production package has no
test bypass and no test seam:

- `TOTPService` has no `devMode` / `testCode` shortcut and no injectable
  verifier. Every code is checked by otplib against the stored secret.
- `TOTPService`, `SessionManager` and `BootstrapService` take no clock or
  recovery-code generator option. They use the system clock and the CSPRNG.
- `BootstrapService` takes no TOTP verifier and no TOTP secret generator. It
  generates the first admin's secret itself and verifies the code itself, so
  no callback can accept an arbitrary code.
- The mTLS helpers have no development pass: no host or `NODE_ENV` admits a
  request that carries no forwarded certificate headers. They trust those
  headers, so the edge proxy must strip client-supplied copies; without
  `validFingerprints`, a forwarded subject with the verify header absent or
  `NONE` is admitted.

The test harness lives in `src/testing` and stays in this repository. It is
behind a hard gate:

1. **Compile-time exclusion.** `tsconfig.json` and Bazel `//:tinyland_auth`
   exclude `src/testing`, so `dist/`, `//:pkg` and the npm tarball never
   contain it. It builds only with `pnpm build:testing` into `dist-testing/`,
   which is git-ignored and not in `files`.
2. **Not exported.** `package.json` has no `./testing` entry, so
   `import '@tummycrypt/tinyland-auth/testing'` fails with
   `ERR_PACKAGE_PATH_NOT_EXPORTED` under every export condition.
3. **Load gate.** The module throws `TestingEntryRefusedError` when it is
   evaluated unless `process.env.NODE_ENV` is exactly `test`. Unset, empty,
   `production`, `development` and every other value refuse. It never reads a
   caller-supplied environment.
4. **Admission gate.** `createTestAdmissionIssuer` also needs
   `TINYLAND_AUTH_TEST_ADMISSION=enabled`. It reads `process.env` when it is
   created and again on every `admit()`.

The helpers are `createTestTOTPService`, `createTestSessionManager` and
`createTestBootstrapService` (test clock, deterministic recovery codes),
`createManualClock`, `createDeterministicBackupCodeGenerator`,
`generateTestIdentity` and `createTestAdmissionIssuer`. Package tests import
them from `src/testing`.

`pnpm check:production-artifact` packs the package, extracts the tarball and
runs `scripts/check-production-artifact.mjs` on it. Bazel
`//:production_artifact_test` runs the same check on `//:pkg`. The check fails
in any of these cases:

- a testing path, testing symbol, the testing sentinel or a removed bypass name
  ships in the package;
- one of those appears in a production Vite bundle of every public entry;
- `./testing` resolves.

`tests/production-artifact.test.ts` injects each kind of leak and checks that
the check catches it.

Production first-admin bootstrap stays the attended `BootstrapService` flow.
Upgrading from 0.x: see [docs/migration-1.0.md](docs/migration-1.0.md).
