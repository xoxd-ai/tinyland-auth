# Auth GF v4 qualification: inert source preparation

As of 2026-09-20, this is a source candidate, not enrollment, an activated
workflow, a passed remote invocation, package publication, or runtime authority.
It belongs to the canonical auth source work in TIN-4182; installation and
rollout coordination remain with TIN-2611. The held auth 0.8 train is unchanged.

## Exact released contract

`.github/lanes.json` declares provider-blind ActionPlan/v4 schema 3 demand:

| Action | Bazel command and existing targets | Result |
| --- | --- | --- |
| `unit-tests` | `test //:test` | `status-only` |
| `package-check` | `build //:pkg //:typecheck` | `status-only` |

Both request the abstract `rbe-linux-x86_64` capability. That declaration does
not assert that any provider supplies it. No runner, endpoint, tenant, catalog,
credential, repository identity, publication, or deployment belongs in this
plan. The exact source revision, plan bytes and module lock are invocation
inputs; a resolver constructs the binding rather than the caller inventing one.

The caller candidate is `docs/gf-v4-qualification.candidate.yml`, deliberately
outside `.github/workflows/`. It references the existing immutable ci-templates
v5.1.0 source commit `32e39ced0008edf4564ebeb173a5e8fbf069e28f`:

`xoxd-ai/ci-templates/.github/workflows/spoke-ci-v4.yml@32e39ced0008edf4564ebeb173a5e8fbf069e28f`

This release admits push and same-repository pull-request events, selecting the
exact push revision or PR head, not the synthetic merge revision. The candidate
limits pushes and PR bases to `main`, grants only `contents: read` and
`id-token: write`, and declares no secrets, tags, manual dispatch, package write,
or publication. The renamed workflow identity must be admitted by current
owner policy; an old-owner redirect is not evidence of that admission.

Status-only actions return terminal status, not exported package files. They
need no `--result-dir` and create no qualified-result directory. In particular,
`build //:pkg` is not artifact export or a publication transaction. The package
target contains a package directory; do not claim that it is already a suitable
`export-regular-files` target. This preparation does not depend on unreleased
ci-templates main, v5.1.1, or proposed publisher inputs.

## Preserve existing authority

The existing `ci.yml`, `publish.yml`, release scripts, versions, package scope,
registry pins and publication permissions remain unchanged. Their results are
not relabeled as v4 evidence, nor are they a fallback for a refused v4 action.

The new plan is qualification-only, not full release-validation parity.
`//:test` and `//:pkg` do not run the complete release metadata guard,
`publint`, or the invitation-authority guard over generated `dist/index.d.ts`.
Keep those existing release gates. Migrating them into qualified Bazel targets,
exporting an actual artifact and publishing it require separate reviewed work.
Do not delete a legacy assertion or release gate merely to activate this caller.

## Module lock and local preparation

GF reads an exact source-bound `MODULE.bazel.lock`; a placeholder, another
repository's lock, an ignored local file, or a checksum without the bytes is not
sufficient. Auth pins Bazel 8.1.1. At the start of this preparation, the module
lock was absent and explicitly ignored. Dependency-resolution diagnostics may
produce the real lock, but they prove neither target execution nor provider
installation. The final diagnostic outcome is recorded below; unresolved lock
generation blocks activation and does not justify weakening transport trust.

No auth-specific lanes generator or validator previously existed. The JSON
plan and YAML candidate are reviewed source; a real module lock is generated
dependency data. Focused contract tests are in
`tests/gf-v4-qualification-contract.test.ts` and included in the existing
`//:test` target's source/runfile inputs. They verify the closed plan and inert
caller, not enrollment or a remote invocation.

Validate the plan against the exact released schema and full JSON Schema
engine, not the current template checkout or a weaker handwritten validator:

```text
python3 <reviewed-v5.1.0-checkout>/scripts/manifest-schema-validate.py \
  <reviewed-v5.1.0-checkout>/schemas/lanes.schema.json .github/lanes.json
```

The checkout must be exactly `32e39ced0008edf4564ebeb173a5e8fbf069e28f`, and the
selected Python must import `jsonschema`. The released schema SHA-256 is
`4fef58645b8cd367a4336a66eaee629388c8a949a06d85becc97cfc1be82e3b8`;
the released validator SHA-256 is
`759f343aadf815a665b6c8319fbc92015a21ea4cf647b1e549f50d3c12b22468`.
Use the explicit schema-path form: `--schemas-dir` and the repo-manifest
composite route repository-manifest schemas, not this action plan. Local
schema, contract-test and dependency-resolution results are diagnostics only.

## Activation prerequisites: separate reviewed transaction

Do not move the candidate into `.github/workflows/`, dispatch it, or call it
qualified until the rollout owner coordinates activation and the following are
verified. A qualifying PR itself would schedule dispatch once a live caller is
added; absence of runner pickup is not an inertness guarantee.

1. Commit the actual reviewed module lock for this exact auth graph and source.
2. Verify the organization's own all-repositories App installation, signed
   current `OwnerInstallation/v1`, `TenantOverlay/v1`, consumer revocation head,
   and exact admitted workflow/ref/event/capability policy. Observe the renamed
   workflow identity explicitly; preserve immutable numeric identities.
3. Obtain the installed dispatch/client image and current provider receipt:
   adopter verifier contribution, independent provider supply and revocations,
   joined current `ResolvedOwnerSupplyCatalog/v1`, and an eligible remote route
   with workers. This document supplies none of those instance identities.
4. Require genuine fresh Actions OIDC and independent App PR admission where
   applicable. The resolver must bind the exact repository, source, raw plan,
   action, module lock, installed Bazel digest and provider-selected closure.
   No cache endpoint, local execution, hosted execution or caller-built binding
   substitutes for missing authority.
5. Review the activation diff and current release contract. Prove the exact
   status-only actions through remote Execute or authenticated cache-hit
   evidence plus measurement attribution; distinguish a cold execution from a
   repeat cache hit. Green Actions status or runner pickup alone is not proof.

Publication remains separate, with its original release checks, artifact
qualification, immutable version, BCR registration and explicit authority. No
package release or application rollout follows automatically from this plan.

## Preparation diagnostic outcome

On 2026-09-20, the plan passed the exact released validator and schema above
with the full `jsonschema` engine. The focused inert-caller suite and existing
`tests/package-authority.test.ts` passed together: 2 files, 10 tests. These
local diagnostics do not qualify remote execution or publication.

The existing managed Bazel launcher passed its transport and volume gates and
reported Bazel 8.1.1. `bazel --batch mod deps --lockfile_mode=update` completed
with exit 0 and no build/test actions. It generated the real
`MODULE.bazel.lock` (lock format 18; 179 registry file hashes, all from the
public Bazel Central Registry). Its SHA-256 at preparation was
`8f008cb7eaee15c9ade5a434770bb977af6a1f4603d06a31815af09531a4b5e8`.
Repeating dependency resolution with `--lockfile_mode=error` also exited 0,
with the same lock digest and no build/test actions.
The generated lock is now tracked; its former ignore entry was removed.
Inspection found no local filesystem URLs/paths, loopback endpoints, embedded
URL credentials or nonempty credential fields. The `secretstorage` occurrence
is public dependency metadata, not a credential.

This was dependency resolution on Darwin, not a Linux remote closure,
execution, cache-hit, worker or provider-admission receipt. No Bazel build/test,
GF dispatch, publication, credential mutation or infrastructure action occurred.
The source lock closes the missing-byte prerequisite only; all installation,
admission, closure and activation gates above remain.
