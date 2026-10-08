# Tinyland Databaseless Auth MVP

This document defines the package-owned auth shape that `tinyland.dev` should
adopt. It is intentionally narrower than a full application login flow:
`@tummycrypt/tinyland-auth` owns reusable auth primitives, while application
routes keep provider callbacks, cookies, UI, and deployment policy.

Executable proof lives in
[`examples/tinyland-databaseless-auth-mvp.ts`](../examples/tinyland-databaseless-auth-mvp.ts)
and is covered by
[`tests/databaseless-mvp.test.ts`](../tests/databaseless-mvp.test.ts).

## Bazel And Package Proof

Package adoption requires qualified remote GF evidence for the exact Bazel
graph, not a local pnpm workspace copy or an ARC runner label.
`//:test` includes the MVP example plus the databaseless auth tests;
`//:typecheck`, `//:release_metadata_test`, `//:invitation_authority_test` and
`//:package_artifact_test` preserve compiler, metadata, generated-declaration
and actual `//:pkg` validation. The caller is currently inert, with no active
replacement for the retired legacy CI/publish pair; see
[GF preparation](gf-v4-qualification-preparation.md).

The runtime TypeScript import remains `@tummycrypt/tinyland-auth`.
Bzlmod plus the append-only Tinyland BCR is the sole first-party delivery authority;
neither npmjs nor GitHub Packages is a delivery or fallback lane. GitHub
tags/releases identify source, while consumers resolve the module and its
`//:pkg` through the reviewed BCR graph. Internal JS packaging and locked
third-party dependencies are not provider publication.

## Authority Planes

| Plane | Package or repo | Responsibility |
| --- | --- | --- |
| Directory actor | application storage adapter | handle-first actor record, optional contact email |
| Auth capability | `@tummycrypt/tinyland-auth` | sessions, TOTP, backup codes, RBAC checks, storage contracts |
| Invitation lifecycle | `@tummycrypt/tinyland-invitation >=0.2.5` | fail-closed role authorization, create, list, revoke, and accept invite tokens |
| Provider identity | app-local adapter | GitHub, future OAuth/OIDC providers, bootstrap/link policy |
| Client evidence | `@tummycrypt/tinyland-fingerprint` plus app client code | FingerprintJS visitor evidence and consent state |
| Overlay evidence | `@tummycrypt/tinyland-otel` plus app server code | Tempo/TraceQL restore and investigation plane |

FingerprintJS and Tempo are not credentials. A valid auth session is bound to a
directory actor and capabilities. Fingerprint and Tempo values may be attached
as metadata/evidence, but missing or changed fingerprint values must not
destroy an otherwise valid session.

## Email-Less Identity

Tinyland identity is handle-first. `AdminUser.email` and invite email fields are
optional compatibility fields, not the source of authority. A Tinyland app may
choose to collect contact email later, but package consumers must be able to
create and authenticate users with only:

- `handle`
- `displayName`
- password hash or provider identity
- role and capability policy
- TOTP/backup-code state when enabled

The MVP test creates a bootstrap admin without an email address. It does not
accept an invitation, trust caller-provided role data, or create a user on
behalf of the invitation package.

## Minimal Flow

```ts
import {
  MemoryStorageAdapter,
  TOTPService,
  createAuthConfig,
  createBackupCodeSet,
  createSessionManager,
  generateBackupCodes,
  hashPassword,
  verifyBackupCode,
} from '@tummycrypt/tinyland-auth';
```

1. Create a storage adapter. The MVP uses `MemoryStorageAdapter`; production
   can use file storage or a tenant-scoped package adapter.
2. Create a handle-first admin user. Email is omitted.
3. Generate and verify a TOTP secret.
4. Generate backup codes, persist the hashed code set, and verify one code.
5. Create an auth session. A fingerprint may be added as metadata, but is not
   required.

## Invitation Acceptance Is External

The executable auth MVP intentionally stops before invitation acceptance. It
does not define an invitation handoff, assign an invitation role, or create a
user from caller-supplied invitation data. Real create/accept/user-create proof
belongs to `@tummycrypt/tinyland-invitation >=0.2.5` composed in a downstream
clean-consumer integration that resolves both package surfaces without a
workspace or vendored fallback.

Version `0.2.5` is the minimum invitation authority because it supplies the
fail-closed role gate and claim-first acceptance ordering. Its per-token
acceptance lock is process-local: it serializes acceptance only
within one Node.js process. It is not a distributed or cross-replica
compare-and-set. Distributed exactly-once acceptance remains open until shared
storage can atomically claim a token.

`tinyland-auth` intentionally retains type-only `AdminInvitation`,
`InvitationConfig`, `InvitationStorage`, and invitation request/response DTOs,
plus invitation-record CRUD on its storage adapters. Those surfaces preserve
data compatibility only; they are not executable mint or acceptance authority.

## What tinyland.dev Should Own

`tinyland.dev` remains responsible for:

- SvelteKit route actions, redirects, and cookies
- canonical invitation configuration and post-accept user creation
- GitHub OAuth callback validation and allowlist policy
- bootstrap policy such as who may become `super_admin`
- UI and form validation
- FingerprintJS collection and consent UX
- Tempo query configuration
- deployment secrets and runtime configuration

The package should not import `tinyland.dev`, GitHub SDKs, SvelteKit route
files, or Tempo clients to prove this MVP.

## Adoption Tests For tinyland.dev

The downstream app should add tests that prove:

- login and session validation do not require a fingerprint
- changed fingerprints do not invalidate valid sessions
- clean-consumer invitation tests use `@tummycrypt/tinyland-invitation >=0.2.5`
  as their only mint/accept authority and preserve its fail-closed role gate
- distributed consumers do not claim exactly-once invite acceptance without a
  storage-backed compare-and-set
- GitHub OAuth creates a package session only after app-local provider checks
- `MODULE.bazel` and Bazel package targets prove released auth-adjacent modules,
  not only pnpm workspace resolution

## Related Linear Work

- TIN-1605: package MVP and docs
- TIN-1606: RBAC matrix normalization
- TIN-1607: `tinyland.dev` invitation package configuration
- TIN-1608: Bazel module adoption proof
- TIN-1610: FingerprintJS and Tempo overlay boundary tests
- TIN-1611: GitHub OAuth provider-bound login contract
