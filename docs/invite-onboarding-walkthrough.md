# Invite-based onboarding walkthrough

> **DRAFT — for operator review, not yet ratified.** (2026-07-11)
> Single-replica deployments only — see the caveat below. This is a
> conceptual/API-level walkthrough grounded in `tinyland.dev`'s actual
> composition, not a new capability this repo ships standalone.

This walks the path from "an admin already exists" to "a second admin is
invited, accepts, and logs in." For how the *very first* admin gets created
with no invite and no existing users, see `docs/bootstrap-from-zero.md`
sections 6 (seed script) and 9 (`BootstrapService`) — that content is not
duplicated here.

## Use `@tummycrypt/tinyland-invitation`, not this package's own `InvitationService`

`tinyland-auth` exports an `InvitationService` from its own public surface
(`src/index.ts` → `src/modules/invitation/index.ts`). **Do not use it for
authorization-sensitive invite minting.** Per **TIN-2780** (tracked, status
"In Review" as of this draft, fix PRs **#33** and **#34** open against this
repo), that exported `InvitationService.createInvitation()` performs no
role-based authorization at all — the caller-supplied `role` flows straight
into the created invitation with no check that the caller is allowed to grant
it. Any caller can currently mint a `super_admin` invite through that path.

The **authoritative, fail-closed** invite flow lives in the separate package
`@tummycrypt/tinyland-invitation` (`0.2.4`, TIN-1607). It is what
`tinyland.dev` actually consumes
(`src/lib/server/auth/invitation-service.ts`), and it is what this walkthrough
uses. If TIN-2780 lands #33 or #34 while this repo still exports the
duplicate service, re-check this doc against the merged shape before
following it further.

## The flow, conceptually

`tinyland.dev`'s `src/lib/server/auth/invitation-service.ts` wires the two
packages together like this (paraphrased from the actual source, not
reproduced verbatim):

- `configure({ ... })` from `@tummycrypt/tinyland-invitation` is called once
  at module load with: file-backed read/write callbacks for an invites file
  and an admin-users file, ID generation, `hashPassword` (re-used from
  `@tummycrypt/tinyland-auth`), TOTP secret/URI/QR generation (re-used from
  `@tummycrypt/tinyland-auth/totp`), an `authConfig` (invite expiry hours,
  bcrypt rounds), an audit-log sink, a `publicUrl`, and —
  load-bearing — a `canCreateInviteForRole` callback.
- That callback is `({ createdByRole, targetRole }) =>
  canManageRole(createdByRole, targetRole)`, where `canManageRole` is
  imported directly from `@tummycrypt/tinyland-auth`'s exported permissions
  API. This is the actual authorization gate: an inviter can only mint an
  invite for a role they themselves outrank.
- The configured singleton is re-exported as `invitationService` and used by
  the app's routes for the rest of the flow.

If a consumer does not supply `canCreateInviteForRole` at all,
`@tummycrypt/tinyland-invitation` does not silently allow everything — it
falls back to its own built-in `defaultCanCreateInviteForRole`, which mirrors
the same strict-hierarchy semantics as `canManageRole` (deny unknown roles,
allow only strictly-higher-authority grants). Wiring `canManageRole`
explicitly, as `tinyland.dev` does, keeps the app's role vocabulary and the
invite package's policy provably in sync rather than relying on two separate
implementations agreeing by convention.

Downstream of `configure()`, the package's own exported surface
(`InvitationService` / `createInvitation` / `acceptInvitation` /
`getInvitation` / `revokeInvitation` from `@tummycrypt/tinyland-invitation`)
carries the flow:

1. An existing admin calls `createInvitation` with the target role and their
   own `createdByRole`. The gate above runs before an invite record is ever
   written; a denied grant throws a typed `InvitationError` rather than
   silently degrading.
2. The invitee visits an accept-invite URL carrying the token, supplies a
   handle/password and enrolls TOTP, and the route calls `acceptInvitation`.
3. On success, a new `AdminUser` at the granted role is created and the
   invitation is marked used. The invitee can now log in through the normal
   `@tummycrypt/tinyland-auth` password + TOTP login path described in
   `docs/bootstrap-from-zero.md` section 7.

## Known gaps — read before wiring this into anything role-sensitive

- **TIN-2780** (this repo, status "In Review"): as above — do not use this
  repo's own exported `InvitationService`; PRs #33/#34 are in flight to
  remove or gate it. This walkthrough's authorization guarantees apply only
  to the `@tummycrypt/tinyland-invitation` path.
- **TIN-2781** (`@tummycrypt/tinyland-invitation`, P1, status "In Progress"
  as of this draft): `acceptInvitation` originally had a check-then-act race
  — two concurrent acceptances of the same unused token with different
  handles could both pass the used-token check and both mint a role-bearing
  admin. **`tinyland-invitation` PR #10 (merged 2026-07-11) closes the
  single-process instance of this race**: a per-token in-process mutex now
  serializes concurrent `acceptInvitation` calls for the same token and
  re-checks `usedAt` inside the lock before a user is created, so within one
  running Node process a token can only ever mint one admin.
  **It does not close the race across processes or replicas.** The mutex is
  explicitly in-memory and per-instance; two separate Node processes (or
  replicas) sharing the same invites file can still both claim the same
  token, because there is no storage-level compare-and-set yet. TIN-2781
  stays open specifically for that gap — treat it as unresolved for any
  deployment shape beyond a single process.

## Single-replica-only caveat

This entire walkthrough — invite minting, acceptance, and the session state
that follows login — is only exercised and only claimed safe for a
**single-process, single-replica** deployment, matching how `tinyland.dev`
runs today. Nothing here has been proven for horizontal scaling, multiple
app instances behind a load balancer, or any cross-replica session or
invite-state coordination. Do not read this doc as endorsing multi-instance
deployment; that would additionally require closing the cross-replica half
of TIN-2781 with a storage-backed compare-and-set, which has not happened.

## Provenance

- `tinyland-auth` `src/index.ts` (line ~312-317) and
  `src/modules/invitation/index.ts` (`createInvitation`, lines ~61-89):
  this repo, `main`. No role-authorization call precedes invitation
  creation — verified by inspection for TIN-2780.
- TIN-2780: `https://linear.app/tinyland/issue/TIN-2780` — fix PRs
  `tinyland-inc/tinyland-auth#33` and `#34`, both open at drafting time.
- `tinyland.dev` `src/lib/server/auth/invitation-service.ts`: `github/main`
  at commit `98c619f954dc985d0aef42ce53a778f566d1f440` — the `configure(...)`
  call, `canCreateInvitationForRole` wrapper around `canManageRole`, and the
  re-exported `invitationService`.
- `@tummycrypt/tinyland-invitation` `src/config.ts` (`InvitationConfig`,
  `configure`), `src/service.ts` (`InvitationService`, `withAcceptanceLock`,
  exported functions), `src/roles.ts` (`defaultCanCreateInviteForRole`,
  `ROLE_HIERARCHY`), `src/index.ts` (public export list): this package,
  `origin/main` at commit `b5931509e01952d3bc95bb47ef20320b2af86e99`,
  version `0.2.4`.
- TIN-2781: `https://linear.app/tinyland/issue/TIN-2781` — fix PR
  `tinyland-inc/tinyland-invitation#10`, merged 2026-07-11. Issue kept open
  ("In Progress") for the remaining cross-replica compare-and-set gap; see
  the PR's own code comment above `withAcceptanceLock` in `src/service.ts`
  disclaiming cross-process/cross-replica coverage.
- `tinyland-auth` `src/core/permissions/index.ts` (`canManageRole`): this
  repo, `main`.
