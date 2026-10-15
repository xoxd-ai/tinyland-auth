# Completed-account TOTP enrollment candidate

TIN-2716 / TIN-4182 / TIN-2843 / TIN-4177. This is unreleased 0.7.2 candidate
source, not package publication, passing tests, or runtime acceptance.

`begin` and `complete` accept the existing `{ userId, sessionId }` onboarding
binding unchanged. These requests continue to write version-1 records. An
explicit `{ userId, sessionId, mode: 'self-enrollment', primaryReauthRef }`
request selects version 2. Version 2 is self-enrollment only; a missing or
onboarding mode on a v2 record is invalid. A v1 record remains onboarding
without normalization or changes to its original material-digest domain.

## Primary authority boundary

The optional `validatePrimaryReauthentication` configuration callback receives
the opaque reference, binding, current durable user, current stored session
and current time. It must resolve a trusted server-held proof, verify its
integrity, and compare its credential binding with the CURRENT password hash
or linked GitHub identity. A browser-provided claims object, existing login
cookie, fingerprint, or cached principal is not primary reauthentication.
No callback, a null result, a thrown error, or an invalid claim denies setup.

After that validation the callback returns only `PrimaryReauthAuthorization`:
`userId`, `sessionId`, `purpose: 'totp.enroll'`, `method: 'password' | 'github'`,
and ISO `issuedAt`/`expiresAt`. The proof lifetime is at most five minutes.
The coordinator independently checks current active/nonremoved identity,
session ownership/expiry, completed-account state, proof ownership/purpose,
freshness, and absent-factor/backup-code state. It rechecks after asynchronous
work and before committing. Callback functions must not recursively enter the
auth gate. The application owns actual password/provider reauthentication;
this package introduces no general proof store or database.

A proof reference and its claims are immutable. Never renew its deadline or
reissue an old reference. The first durable pending write binds the reference
to one attempt. Same-attempt resume is permitted; starting a different attempt
from the same still-live proof is denied even after pending expiry, successful
commit, or out-of-band factor removal. A bounded active-use ledger (at most
256 unexpired entries) is carried within the same v2 journal, not a second
store. Starting a new attempt retains all still-live bindings and prunes only
expired immutable proofs. Onboarding cannot overwrite those live bindings.
Do not externally delete/consume the primary proof before a commit: journal
publication owns the crash-safe binding/consumption decision.

## Projection and recovery

Self-enrollment's frozen `userPatch` has exactly `totpEnabled: true` and
`totpSecretId`. It cannot change onboarding, role, grants, profile or sessions.
The application's raw `project` callback MUST re-read the current owner and
reject removed/inactive identities, changed ownership or conflicting factor
and recovery material. It must preserve already-used backup codes and TOTP
counters while replaying matching partial material. Do not reuse the old
onboarding-only projection without a version-discriminated v2 branch.

A durably committed operation can finish projection after primary-proof
expiry or initiating-session revocation: replay is completion of an accepted
write, not new authentication. An applied retry returns only its receipt to
the original still-current owner/session/mode and never returns factor or
backup-code material. Setup material requires current primary proof. A failed
projection keeps guarded auth closed; a receipt never reprojects spent codes.
An applied receipt acknowledges historical completion, not the present factor
state after later recovery. The app must re-read current durable flags for UI.

## Rollout and rollback

Before enabling the first self-enrollment route, deploy both this canonical
reader and the matching app projection/primary-proof resolver. V2 starts at
the first pending setup write, not at verification. Old readers reject v2
journals, so an image rollback to a v1-only runtime is NOT safe thereafter.
Keep a compatible reader/projection in rollback images or roll forward under
the existing single-writer gate. Do not delete, downgrade, replay from backup,
or reset a journal/factor/recovery file to make an old image start. No storage
or key migration, new secret, second writer, publication or public federation
authorization is implied.

The existing Bazel `//:test` glob includes the v2 denial, mode-confusion,
single-reference binding, credential-change, replay and v1-compatibility
regressions. They remain unrun until an execution lane is admitted. Required
acceptance additionally includes real existing-admin login, primary reauth,
setup/restart, TOTP completion, one-use recovery and same-session/other-session
denials with no credential material in receipts or logs.
