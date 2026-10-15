# Durable own-factor retirement (TIN-4177 / TIN-4435)

This is an unreleased source candidate, not deployment or execution evidence.
The existing reader R1 using auth `3c127a29` does not recover this journal.
An R2 reader containing this coordinator and the application recovery bridge
must be qualified and installed before any writer may initiate retirement.
No environment override or source-phase activation is supplied here.

## Application boundary

`FileTotpRetirementCoordinator` is exported from `./storage`. Inject the existing
reentrant enrollment coordinator's exclusive gate, a dedicated directory under
the already-created durable auth root, existing >=32-byte signing-key custody,
and `TotpRetirementStorage`. Do not inject an application wrapper which itself
calls retirement recovery. Do not change generic `IStorageAdapter`, PostgreSQL
or Redis consumers; these are additive concrete-file capabilities.

Application readiness order is enrollment recovery, bootstrap recovery,
invitation recovery, retirement recovery, then the requested auth operation.
All participating authentication, session, factor and account writers must use
this one process-wide gate. There is no cross-process CAS or multi-replica claim.

The expected-delete and flags-clear capabilities have this same gate requirement
even when called directly. All journal, credential and account directories and
their ancestors must remain operator-owned, without independent filesystem
writers. Maintenance must quiesce the application rather than mutate these paths
concurrently. The lstat/open/unlink and owner-check/update sequences reject unsafe
observed state, but are not atomic protection against an out-of-gate process
swapping a parent, leaf or account record between those operations. Neither the
coordinator nor these capabilities claim that stronger filesystem adversary model.

`retire({userId, handle, sessionId, authorize})` takes server-held identity, never
an arbitrary submitted target. After validating the current completed principal,
session and credential material, it invokes the trusted application callback.
That callback must call the real `consumeActionStepUp` for `factor.disable`,
bind its target state to the supplied factor generation and recovery-set digest,
and compare the consumed factor binding to the current application factor
binding. A structurally valid callback result alone is not authentication; the
callback is part of the trusted integration. Route origin, CSRF, rate budgets,
source-phase admission and actual TOTP proof remain application responsibilities.

The callback returns the strict consumed receipt or
`{kind:'not-consumed', result}` for a challenge/denial. The latter performs no
revocation, flag change or retirement-journal publication. After consumed proof,
the coordinator rereads current authority and material. The stable generation
excludes TOTP use counters, so legitimate verification advancement is accepted;
the committed deletion snapshot includes the latest counters. Changed generation,
recovery set, principal or expired/revoked session prevents commitment.

## Commit and replay

Each consumed authorization receipt gets its own private, sealed record with a
digest-derived filename. A `committed` record contains immutable owner/handle,
operation and authorization digests, generation/snapshot/recovery-set digests,
the application factor binding and commit time. It contains no plaintext secret,
displayable recovery code, encrypted factor, recovery-code hash or bearer session.

Only after file fsync, rename and directory fsync acknowledgment does projection:

1. Durably revoke every session for that owner and verify absence.
2. Delete the exact expected factor and recovery set, acknowledging their parent
   directories even when a previous interrupted unlink already removed a file.
3. Durably clear only factor-enabled/alias flags and verify every projection.
4. Publish an `applied` receipt through the same durable publication protocol.

Credential deletion throws on uncertainty, nonmatching material, symlink or
hardlink; it does not reuse the legacy boolean deletion methods. Recovery accepts
missing old material but rejects replacement material. It needs no initiating
session, unexpired proof or new step-up: commitment is the frozen authority.
It remains enabled when new authority writes are source-closed.

Journal reads acknowledge the parent/journal directories before observing a
potential earlier uncertain rename. Any unsuccessful projection leaves the
committed record and blocks subsequent guarded auth operations until recovery.
The app must not retry factor deletion independently or report success merely
because a file disappeared. Only the terminal durable receipt is success.

Applied records are immutable history and are never reprojected. Trusted
`readReceipt({receiptId,userId})` returns a matching receipt without touching a
later enrolled generation. Reusing that consumed authorization for a new
retirement conflicts. A fresh generation plus fresh action proof may create a
new operation. Enrollment journals, including `primaryReauthUses`, are not edited
or removed. The finite journal cap is 4096 retained operations; exhaustion requires
operator review, not automatic deletion of replay history.

## Qualification

`tests/file-totp-retirement.test.ts` is included by existing Vitest and Bazel
`//:test` globs; source also falls under `//:typecheck`/package source globs.
Tests cover nonconsumed proof, material/current-session changes, crash recovery,
expected deletion, preserved enrollment history and later-factor replay safety.
No local or remote test/build/typecheck result is claimed by this document.
R2 recovery fixtures and the consuming application's source-closed/active bridge
fixtures must qualify before a writer release. R1 is not a safe rollback reader
after the first retirement journal is emitted.
