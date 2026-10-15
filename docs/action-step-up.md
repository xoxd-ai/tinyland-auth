# Action-bound TOTP step-up candidate

This is unreleased canonical source, not a passing test, package publication,
or runtime authorization. The mothership owns the finite route policy, normal
current-principal authorization, exact-origin/CSRF checks, per-account/IP
budgets, UI, and an outer `withReadyAuth` gate. This store must have one process
writer and a private dedicated directory; it is not a distributed transaction.

`FileActionStepUpStore` accepts the existing auth signing key through
`signingKey` (`AUTH_SECRET`, otherwise `TOTP_ENCRYPTION_KEY`, at least 32 UTF-8
bytes). Its caller computes fresh 64-hex keyed bindings for the exact session,
credential, authority, factor generation, normalized intended mutation, and
relevant current target state. It must not use an unkeyed password digest.
The store additionally HMAC-binds the complete action/resource/identity tuple.
Only sealed records, HMAC reference and resource identifiers, and bounded
timestamps/failure counts are persisted; no raw session, password, challenge,
permit, receipt, or mutation payload is written.

The application first authorizes the exact action and calls `issue(binding)`;
the returned challenge is not a permit. Its verification route invokes
`verify({ challengeId, identity }, verifyFactor)` under the auth gate. The
trusted callback must check a fresh six-digit TOTP code and durably advance
the canonical used-step replay boundary exactly once. Backup codes, login
assurance, fingerprints, and generic cookies are not substitutes. A verified
response contains a distinct `permitId`, returned only after the sealed
verified state and containing directory are synced. Reverification never
re-discloses it. If the response or durable write is lost, the user starts a
new explicit challenge. Expiry is absolute and never exceeds five minutes.

The original mutation route recomputes the same binding from durable current
records, checks its ordinary permission again, and calls
`consume({ challengeId, permitId, binding })` before any business side effect.
Only the first exact consume wins, and its tombstone is synced before a receipt
is returned. A later mutation failure does not restore the permit. The receipt
contains only an opaque ID, actor ID, action/resource ID, and the nonsecret
factor-generation witness. The caller must compare that witness to a fresh
factor binding before dependent publication (notably federation activation).

Records are pruned only after expiry; an invalid seal or unavailable fsync
fails closed. Every queued operation syncs the directory before reading, so a
post-rename sync failure cannot expose unacknowledged state. A verified record
whose response failed still cannot be consumed: its raw permit reference was
never stored or disclosed. Old readers do not understand these files; deploy
the matching source before enabling a route, preserve the directory on
rollback, and do not introduce a second writer or a new signing secret.
