# Restart-durable ordinary TOTP enrollment

`FileTotpEnrollmentCoordinator` is an additive `./storage` capability for an
existing, active user's onboarding. It is not the first-super-admin bootstrap
service and does not require the held auth 0.8 bootstrap interfaces. This source
candidate needs canonical package/BCR release before consumer adoption.

## Ownership and deployment

Exactly one application process writes the durable auth root. The mutex is
process-local, including between instances using the same resolved directory;
it is not a cross-process lock, multi-replica CAS or cross-node guarantee. Use
one singleton and path, not symlink aliases or different projection callbacks.
Journal files belong on durable deployment storage, not an ephemeral layer.

Every protected auth decision and mutation must share the recovery gate:
principal/session resolution, login/TOTP verification, factor/code changes,
onboarding, removal, invitation mutations and authorized publishing. Read the
current canonical principal, not cached session flags. Keep the gate around
the authorization check and local storage change, but release it before
provider exchanges, remote ActivityPub delivery and unrelated network work.
Always await mutations; do not fire and forget storage writes.

The package owns pending custody, verification, frozen completion, receipts and
recovery ordering. The app owns routes, cookies, CSRF, policy, rate limits,
canonical lookup, durable projections and post-commit session refresh.
Invitation lifecycle policy remains in `tinyland-invitation`.

## API and application callbacks

```ts
import { FileTotpEnrollmentCoordinator } from '@tummycrypt/tinyland-auth/storage';

const enrollment = new FileTotpEnrollmentCoordinator({
  directory: '/durable/auth/totp-enrollment',
  totp, // Existing TOTPService; never enable a production test-code bypass.
  loadCurrent: readUncachedPrincipalSessionAndFactors,
  project: projectEnrollmentDurably,
  ttlMs: 10 * 60 * 1000,
});
```

The two callbacks are application implementations, not additional exports:

- `loadCurrent({ userId, sessionId })` returns `{ user, session, totpSecret,
  backupCodes }`, with `null` for absence. Use raw adapters and uncached, unique
  identity lookup; do not re-enter the gate. The coordinator requires an active,
  known-role principal and the exact live session. New enrollment requires
  pending onboarding, an integer step 1–3, and no enabled factor, factor ID,
  stored factor or backup-code set.
- `project(completion)` durably and idempotently writes `totpSecret`,
  `backupCodes`, then only `userPatch`, through raw adapters. Never create a
  principal, change identity/role/permissions/removal state or refresh a session
  here. The patch enables TOTP, keeps onboarding pending and advances its step
  to at least 2; preserve a greater existing step.

Projections must reject unrelated existing factor/code material. For identical
material already projected, preserve any greater consumed TOTP step and used
backup-code flags. `FileStorageAdapter` acknowledges JSON writes after file sync,
rename and directory sync. Its credential reads return `null` only for missing
files; unreadable, malformed or incorrectly bound records throw rather than
authorizing replacement. A separate identity repository must durably publish
its projection too: plain unsynced `writeFile` is insufficient before an applied
receipt. All live writers must cooperate with the gate.

A matching visible projection after an earlier write failure is not itself a
durability acknowledgement: rename may have succeeded while directory sync
failed. On retry, durably republish the same preserved material (or explicitly
sync its directory) before returning. Only applied receipts skip projection.

```ts
// Inject enrollment.withReadyAuth.bind(enrollment) as the invitation package's
// mutation gate. Compose BOTH recovery barriers before protected app traffic.
const withReadyAuth = <T>(operation: () => Promise<T>) =>
  enrollment.withReadyAuth(async () => {
    await invitations.recoverPendingAcceptances();
    return operation();
  });

// Binding comes from the server's live session, never request user IDs.
const binding = { userId: session.userId, sessionId: session.id };
const setup = await withReadyAuth(() => enrollment.begin(binding));
// Render setup.secret/qrCodeUrl/backupCodes only on the authenticated setup page.
// Carry setup.attemptId, NOT secret or backup codes, in cookies/forms.
const receipt = await withReadyAuth(() => enrollment.complete({
  ...binding, attemptId: submittedAttemptId, token: submittedTotpCode,
}));
// Refresh session state from current identity only after completion, under the
// app gate. Receipt is acknowledgement, NOT authority to reapply user flags.
```

`withReadyAuth` supports nested async calls without deadlock and serializes
nested siblings, including `Promise.all`. Projection callbacks cannot re-enter
the gate. `recover()` explicitly runs startup/retry recovery; subsequent gate
entries also recover after runtime failures. A startup-only barrier is not
sufficient. Onboarding completion still needs its own factor/prerequisite guard.

## Commit, expiry and restart

1. `begin` durably stores one pending attempt per user, with a random 192-bit
   attempt ID and principal/session binding digest. Secret and displayable
   backup codes are encrypted with the existing TOTP encryption service.
   Files use `0600`; newly created journal directories use `0700`.
2. The same live session resumes the same unexpired material. Other sessions
   cannot take it over. Expiry is at most ten minutes and reads never extend it.
   Replacement after expiry requires fresh authorization.
3. `complete` verifies TOTP, retains the matched step, rechecks current state
   and expiry, then atomically publishes one **committed** record containing
   encrypted factor, code hashes, narrow patch and material-digest receipt.
   This consumes pending authority; no projection precedes the commit.
4. Projection runs exclusively. After every projection durably succeeds, the
   record becomes **applied**, retaining its non-secret receipt and dropping
   obsolete material. Session refresh is downstream of this boundary.
5. Recovery validates records and encryption-key availability, then replays
   only committed-but-unapplied operations before protected callbacks run.
   An indeterminate rename/directory-sync result must be acknowledged before
   replay or access. Corruption, wrong keys or failed projection leave auth
   traffic closed; there is no fallback around the gate.
6. Applied retry by the same live principal/session returns only its receipt,
   with **zero projection writes**. It never restores old factors or resets
   consumed backup codes. A later authorized fresh attempt replaces the prior
   receipt; older attempt IDs then conflict.

The operation record is recovery authority, not a second live identity store.
Existing files remain live projections after application. Unpublished `.tmp`
files have no authority. Do not delete committed records to bypass recovery.
The configured filesystem must honor sync and atomic rename; refusal fails
closed. No claim is made about cross-node locking or storage-loss availability.

`tests/file-totp-enrollment.test.ts` is registered through existing Vitest and
Bazel `//:test` globs. Local results are diagnostics, not remote GF execution
proof; building a test target alone does not execute its tests.
