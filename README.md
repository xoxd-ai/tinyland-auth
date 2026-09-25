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

The released 0.7.1 package has these ordinary storage implementations:

- **Built-in**: `MemoryStorageAdapter`, `FileStorageAdapter`
- **Separate packages**: `@tummycrypt/tinyland-auth-pg` (PostgreSQL),
  `@tummycrypt/tinyland-auth-redis` (Upstash Redis)

The PostgreSQL and Redis packages implement only the legacy adapter surface.
They do **not** support the atomic first-user bootstrap protocol described
below. Do not use either package for that workflow until its dedicated durable
CAS implementation lands and passes conformance.

The unreleased 0.8 interface requires every implementation to provide the
native tenant-scoped
`claimFirstUserBootstrap`, `finalizeFirstUserBootstrap`, and
`getFirstUserBootstrapReceipt` protocol. A claim is an inert actor marker;
finalization atomically makes the user, bcrypt password hash, fresh TOTP
factor, and fresh backup-code records usable and writes an immutable replay
receipt. `isValidInertFirstUserClaim` is exported from `./storage` and the root
package. The same surface exports canonical finalization validation, material
digest, receipt creation/parsing, and
`runFirstUserBootstrapStorageConformance`, a framework-neutral backend test
runner. It passes a fresh normalized tenant UUID to each harness factory so a
durable backend can isolate every case. A future durable adapter must implement
the transaction in its own backend. `createFixedTenantStorageAdapter` only
injects a normalized tenant id
and forwards normalized payloads; it does not create atomicity by composing
ordinary writes and does not make the current PG/Redis packages compatible.

The built-in memory instance and file data root are each a single-tenant
boundary, matching their existing unscoped user/session APIs. Use one instance
or root per tenant. Future multi-tenant durable backends must scope the same
protocol by the tenant argument required by `TenantScopedStorage`. The current
PG/Redis releases do not implement or support this unreleased 0.8 surface.

Accepting a first-user claim revokes every session already present in that
single-tenant boundary, and session creation remains disabled until
finalization. After finalization, normal sessions are unchanged. SvelteKit role
and permission guards use the matching `event.locals.user` loaded from storage,
not an embedded session role by itself, so a pre-bootstrap session cannot retain
privileged authority through a stale role claim.

For a real 0.7 file root that already has users but no bootstrap receipt,
`createUser` performs a one-time reconciliation before adding the next user.
The legacy root must contain exactly one active, unlocked `super_admin`; zero or
multiple candidates fail closed. The file adapter atomically publishes an
immutable reconciliation marker under `totpDir`, protects that owner's user
record from deletion, and then permits ordinary user creation (including the
storage step used by invitation acceptance). A legacy marker is not a forged
0.8 bootstrap receipt, and ambiguous legacy ownership requires operator repair.

`FileStorageAdapter.getFirstUserBootstrapPath(tenantId)` always resolves below
the configured `totpDir`. Completion uses a constant-space two-slot lock and
atomic record rename. A winner atomically creates one owner; release stages and
then publishes hard links to its privately held inode without unlinking any
current-owner path. After publication, the releaser performs no pathname read
or delete, so a replacement owner is preserved and fails closed. The
next winner compacts only the previous, provably released slot while owning the
other slot. Acquisition inspects a fixed set of paths, holds no contender file
descriptors, and clamps retry sleeps to the remaining timeout. Corrupted,
moved, tenant-mismatched, or JSON `null` claim/receipt state fails closed. The
memory and file adapters run the same storage conformance suite.

An ordinary active-owner timeout should be retried. If timeouts persist after
all known participants have stopped, owner liveness is ambiguous on a shared
filesystem and recovery must be attended. Stop every process sharing the file
root, preserve the lock directory and bootstrap record for diagnosis, verify no
owner can still run, and only then retire the lock directory. Never remove or
rewrite an owner/release artifact while any adapter process may still be active.

The guided `BootstrapService` additionally requires a `tenantId` and a
`BootstrapAttemptStore`. Browser-visible `BootstrapState` contains only a
version and high-entropy attempt id (192 random bits by default). Password
hashes, raw TOTP secrets, plaintext backup codes, and prepared finalization
material remain in the server-side attempt store.
`MemoryBootstrapAttemptStore` is explicitly
single-process; horizontally scaled consumers must provide durable
compare-and-set custody, enforce attempt expiry, reject stale attempt digests
when freezing finalization, and pass
`runBootstrapAttemptStoreConformance` before use. Receipt replay never returns
pending credential material, and `complete()` never emits backup codes; the
one-time display is the `initiate()` response. Bootstrap attempts use the
storage protocol's fixed ten-minute (600,000 ms) claim window. The exact
boundary remains valid; 600,001 ms is expired, with no clock-skew grace added
to expiry acceptance. `systemConfigured` proves
that finalized authority metadata is present and its TOTP ciphertext decrypts;
it is not a live authenticator-code canary.

`BootstrapService` does not authenticate or authorize whoever calls
`initiate()`. A downstream integration must place initiation behind an
operator-only local control, loopback-only command, or equivalently private
administrative gate before invoking it. Do not expose initiation as a public or
merely rate-limited first-run endpoint. The opaque browser state protects
credential custody; it does not provide initiation authorization.

The conformance harness includes an `advanceTime(ms)` hook so durable stores
must prove a live prepared attempt becomes unreadable, stops blocking the
tenant, and permits a replacement after expiry. Rejecting only already-expired
input is not sufficient.

This is only the unreleased 0.8 source contract. No 0.8 package, PostgreSQL or
Redis implementation, registry promotion, or consumer adoption is claimed.

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
storage-layer compare-and-swap for general mutable auth records. The atomic
first-user bootstrap methods are the narrow exception; they do not make every
other file-adapter method a distributed transaction. Consumers running more
than one replica need a
CAS-capable adapter or must stay pinned to a single replica. The current
PostgreSQL/Redis packages may serve ordinary auth records but remain
unsupported for the unreleased atomic bootstrap protocol. The
`ha.tinyland.dev/*` exception recorded on
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
