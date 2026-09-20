# Auth 0.7.2: provisional compatible-launch source candidate

## Disposition and scope

On 2026-09-20 the operator approved **separate compatible launch candidates**
for the existing-admin, single-writer launch. This permits source/version
preparation; it is not permission to merge, tag, publish, promote BCR, adopt
consumer pins, activate workflows or change runtime state. TIN-4182 owns this
auth source candidate; TIN-2611 continues to own GF rollout coordination.
The current scope receipt is TIN-2716 comment
`6d68fbe2-d37a-4ea3-8d80-2927dec2979b`; the selected peer receipt is TIN-2416
comment `8203f78c-a6f9-4be3-9fa9-b5247cae07a1`.

This narrowly supersedes the earlier operational invitation hold for that
source/version preparation only. It does not adopt or release the breaking
auth 0.8 / invitation 0.3 trains. Preserve auth
[#41](https://github.com/xoxd-ai/tinyland-auth/pull/41) and
[#42](https://github.com/xoxd-ai/tinyland-auth/pull/42), and invitation
[#12](https://github.com/xoxd-ai/tinyland-invitation/pull/12) and
[#14](https://github.com/xoxd-ai/tinyland-invitation/pull/14), as held. The
[older operational hold](https://github.com/xoxd-ai/tinyland-auth/pull/41#issuecomment-4964847924)
and [latest explicit source-train hold](https://github.com/xoxd-ai/tinyland-auth/pull/41#issuecomment-4983990157)
remain historical evidence; source preparation is not runtime unfreezing.

Compatibility review compares published v0.7.1 source
`17650d218508dfcbceab134266fe8cb5640e4f97` with the prepared source at
`9f827c5fd463d00562e5ae5e271864016b977308`, before this metadata-only follow-up.
The proposed patch candidate is 0.7.2, not a reservation of the number.

## Compatibility and deployment limits

- Existing export paths, `IStorageAdapter` and bootstrap APIs are retained.
  `FileTotpEnrollmentCoordinator` is an additive, opt-in `./storage` export for
  ordinary onboarding of an existing active user, not first-admin creation.
  Follow [its integration contract](file-totp-enrollment.md), including the
  shared recovery gate and durable application projections.
- Existing administrative permission strings and default grants remain.
  `content.own.publish` and `federation.own.deliver` are new, explicit-user-only
  capabilities, including for `super_admin`. They grant no ownership by
  themselves; consumers must check the current principal and content owner.
  Consumers enumerating the permission vocabulary must account for new values.
- Credential hardening intentionally changes failure behavior: unreadable,
  malformed or identity-mismatched TOTP/backup-code records throw instead of
  appearing absent. Only missing files return `null`; this is not a promise of
  compatibility with invalid persisted credentials or fail-open error handling.
- File writes now acknowledge file sync, atomic rename and directory sync.
  The supported launch requires persistent storage honoring those operations
  and one cooperating application process. Filesystems that refuse them fail
  closed. No cross-process lock, multi-replica CAS or storage-loss guarantee is
  provided; the coordinator's mutex is process-local.
- No dependency pins, package scope, active workflows or consumer pins change
  in this metadata preparation. No old held-PR implementation is incorporated.

Deferred work remains deferred: immutable first-super-admin bootstrap receipts,
PG/Redis adapter convergence, versioned RBAC and principal-bound invitation
APIs, distributed acceptance, canonical transactional role/session changes and
attended multi-replica proof. Ordinary enrollment does not establish those
guarantees or migrate every consumer's invitation TOTP custody.

## Occupancy and release authority

Read-only checks on 2026-09-20 found no v0.7.2 GitHub tag or release in
`xoxd-ai/tinyland-auth`, and no 0.7.2 directory or metadata entry under active
`bazel-registry/modules/tummycrypt_tinyland_auth`. Published/tag/BCR maximum
remains 0.7.1. GitHub Packages occupancy is **unverified**: the available read
credential lacks `read:packages`. Recheck every distribution authority at the
actual release boundary; this source version is not globally reserved.

The existing auth CI can publish on a version-tag push; its publish workflow
also handles published GitHub Releases. Neither event is a harmless metadata
operation. Both still require their existing release gates. The configured
GitHub Packages destination remains `@tinyland-inc/tinyland-auth`; the renamed
owner/destination and installed App authority need release-owner reconciliation.
npmjs remains disabled. This candidate changes none of those workflows.

BCR promotion is a separate reviewed registry change: add a new immutable
version directory containing the actual source archive/SRI and module metadata,
plus the module's version index. Do not overwrite an occupied version, invent
an archive hash or treat a package tag as registry publication.

## Validation boundary

Lightweight source checks are `node scripts/check-release-metadata.mjs` and
`git diff --check`. They establish metadata alignment, not package behavior.
Scoped local tests and dependency-resolution replay are preparation diagnostics,
not authority to activate a remote caller or publish. Prior diagnostics in
[GF preparation](gf-v4-qualification-preparation.md) describe their original
source revision, not qualification of this candidate.

The metadata follow-up passed all 11 cases in the two package-authority and
inert-qualification suites on 2026-09-20 UTC. The metadata guard passed normally
and with a simulated matching `v0.7.2` tag context, and correctly rejected a
simulated `v0.7.1` context (exit 1). These environment-only diagnostics created
no tag or release. Whitespace checks passed.

Managed Bazel 8.1.1 strict dependency replay correctly rejected the old
root-version extension usage digests. Dependency-only update regenerated
exactly three `usagesDigest` values (Node, pnpm and TypeScript), without changing
dependency pins, registry hashes or generated repository specs. Subsequent
`--lockfile_mode=error` replay passed without changing lock SHA-256
`5a2668faaea0a7ccc7eb041f89299472134c1f3689303775ad4378b4aace1c6c`.
No lock digests were hand-edited. This Darwin dependency diagnostic is not a
Bazel build/test or proof of Linux remote closure. Runtime suites, compiler
outputs and package artifact checks were not repeated in this metadata pass.

The inert qualification plan declares `test //:test //:release_metadata_test
//:invitation_authority_test` and `build //:pkg //:typecheck`. Its released
schema validation, provider installation, admission, remote execution receipts
and activation remain the separate gates documented in GF preparation. The
generated-declaration invitation guard requires real compiler output; a source
metadata check cannot replace it. Existing `publint`, artifact qualification,
tag/version checks, collision checks, release authorization and BCR promotion
also remain required. Status-only qualification does not export an artifact or
authorize publication.
