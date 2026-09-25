# @tummycrypt/tinyland-auth

Production-grade authentication system with TOTP, RBAC, and pluggable storage.

## Consumption And Release Authority

The TypeScript import API stays under `@tummycrypt/tinyland-auth`.
Bzlmod plus the append-only Tinyland BCR is the sole first-party delivery authority
([TIN-89](https://linear.app/tinyland/issue/TIN-89),
[TIN-1629](https://linear.app/tinyland/issue/TIN-1629)). GitHub tags/releases bind
source identity; neither npmjs nor GitHub Packages is a delivery or fallback lane.
Historical provider artifacts and tags remain untouched.

Consumers pin `tummycrypt_tinyland_auth` in `MODULE.bazel` and link its `//:pkg`
through Bazel's `npm_link_package`, not a first-party package-manager specifier
or vendored copy. `npm_package`, `npm_translate_lock`, Node and locked pnpm
dependencies are internal build/consumer mechanics, not provider publishers.
The manifest's `private: true` and `npm_package(publishable = False)` prevent
package-provider publication without changing TypeScript import paths.

The legacy CI/publish pair and network `npx` Bazel fallback are retired in this
source candidate. GF qualification remains **inert**: the caller stays under
`docs/`, pending exact released-contract and admission review. No active remote
checks are claimed. The finite graph retains `//:test`, `//:typecheck`,
`//:release_metadata_test`, `//:invitation_authority_test`, `//:pkg`, and
`//:package_artifact_test`; the last checks the real Bazel package and runs
locked publint without npm/pnpm packing. See the
[GF qualification boundary](docs/gf-v4-qualification-preparation.md) and
[0.7.2 candidate disposition](docs/release-candidate-0.7.2.md).

## Exports

- `.` — core auth: session management, password hashing, permissions, RBAC
- `./sveltekit` — SvelteKit integration: hooks, guards, CSRF, session cookies
- `./sveltekit/server` — server-only hooks, guards, cookies and ownership checks;
  excludes client rune stores and can be imported by plain Node consumers
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

### Ordinary onboarding enrollment (source candidate)

The additive `./storage` export `FileTotpEnrollmentCoordinator` provides
session-bound server-held pending TOTP material and committed/applied recovery
receipts for the existing single-process databaseless deployment. Applications
supply durable projections and route protected auth reads and mutations through
the shared recovery gate. It does not adopt the held 0.8 bootstrap train or
provide multi-replica guarantees. See the
[API and integration contract](docs/file-totp-enrollment.md).

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
| `super_admin` | governance-spine | System owner; every administrative permission. Own publication/federation requires explicit grants. |
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
