# Auth GF v4 qualification: inert source preparation

As of 2026-09-21, this is a source candidate, not enrollment, an activated
workflow, a passed remote invocation, package publication, or runtime authority.
It belongs to the canonical auth source work in TIN-4182; installation and
rollout coordination remain with TIN-2611. The held auth 0.8 train is unchanged.

## Exact released contract

`.github/lanes.json` declares provider-blind ActionPlan/v4 schema 3 demand:

| Action | Bazel command and existing targets | Result |
| --- | --- | --- |
| `unit-tests` | `test //:test //:release_metadata_test //:invitation_authority_test //:package_artifact_test` | `status-only` |
| `package-check` | `build //:pkg //:typecheck` | `status-only` |

Both request the abstract `rbe-linux-x86_64` capability. That declaration does
not assert that any provider supplies it. No runner, endpoint, tenant, catalog,
credential, repository identity, publication, or deployment belongs in this
plan. The exact source revision, plan bytes and module lock are invocation
inputs; a resolver constructs the binding rather than the caller inventing one.

The caller candidate is `docs/gf-v4-qualification.candidate.yml`, deliberately
outside `.github/workflows/`. It references the existing immutable ci-templates
v5.1.1 source commit `ae836d8400d5784d74af4fecc020f225d1c2d08e`:

`xoxd-ai/ci-templates/.github/workflows/spoke-ci-v4.yml@ae836d8400d5784d74af4fecc020f225d1c2d08e`

This release admits push and same-repository pull-request events, selecting the
exact push revision or PR head, not the synthetic merge revision. The candidate
limits pushes and PR bases to `main`, grants only `contents: read` and
`id-token: write`, and declares no secrets, tags, manual dispatch, package write,
or publication. The renamed workflow identity must be admitted by current
owner policy; an old-owner redirect is not evidence of that admission.

Status-only actions return terminal status, not exported package files. The
v5.1.1 carrier now supplies its client `--result-dir` under `RUNNER_TEMP`; that
argument does not change this plan into an export action. In particular,
`build //:pkg` is not artifact export or a publication transaction. The package
target contains a package directory; do not claim that it is already a suitable
`export-regular-files` target. The exact released v5.1.1 carrier was reviewed
on 2026-09-21 and selected for this inert source only. Its result-directory
addition grants no installed admission, output-publication or activation claim.
The previous v5.1.0 pin remains historical diagnostic provenance below; no
ci-templates main or future release is adopted implicitly.

## Retire provider publication, preserve graph validation

TIN-89 and TIN-1629 make Bzlmod plus the append-only Tinyland BCR the sole
first-party delivery authority. GitHub source tags/releases bind source
identity. npmjs and GitHub Packages are neither delivery lanes nor fallbacks.
The 2026-09-21 correction deletes the legacy CI/publish pair, provider
permissions/inputs/secrets and the network `npx` Bazel bootstrap, while keeping
historical tags/artifacts unchanged. The existing source `//:pkg` remains an
internal Bazel package directory; `publishable = False` and manifest
`private: true` prevent provider publication. This does not add a publisher.

There are now no active workflow YAMLs in this source candidate. Missing GF
admission means qualification cannot run; it does not mean success or authorize
an old workflow, local execution, hosted runner or bespoke wrapper fallback.
The [0.7.2 candidate](release-candidate-0.7.2.md), held auth 0.8 train, unchanged
dependency/toolchain pins and separate release approval remain intact.

Validation survives as finite graph targets. The metadata test checks source
version/changelog alignment, not release-time GitHub tag identity. The
invitation-authority test depends on `:tinyland_auth` and explicitly sets
`include_types = True`, supplying actual generated `dist/index.d.ts` rather
than a fixture. `//:package_artifact_test` validates the real `//:pkg` identity,
export map, dependencies and nonempty JS/declaration files, and calls locked
publint with `pack: false` over those exact bytes. No npm/pnpm pack or provider
publish command is invoked. Warnings retain the old publint severity; errors
fail. The declaration check, package-artifact test and ordinary unit tests all
belong to the `test` action, not merely a build.

The plan is qualification-only. Artifact export, exact source archive/SRI,
tag/version validation, append-only BCR promotion and external consumer proof
remain release work. Test runfiles include all workflow YAMLs so a newly added
active caller cannot be hidden from the retirement/inertness contract. The
removed legacy TypeScript 6.0.3 task is not claimed as a retained remote check;
the existing Bazel compiler remains 5.9.3.

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
python3 <reviewed-v5.1.1-checkout>/scripts/manifest-schema-validate.py \
  <reviewed-v5.1.1-checkout>/schemas/lanes.schema.json .github/lanes.json
```

The checkout must be exactly `ae836d8400d5784d74af4fecc020f225d1c2d08e`, and the
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

Source release and BCR promotion remain separate, with meaningful graph
checks, exact artifact/source evidence, immutable version and explicit
authority. No provider package publication or application rollout follows
from this plan.

## Preparation diagnostic outcome

On 2026-09-20, the then-current plan and v5.1.0 caller at
`32e39ced0008edf4564ebeb173a5e8fbf069e28f` passed its released validator/schema
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

The subsequent source follow-up adds explicit Bazel execution targets for the
unchanged release-metadata and invitation-authority scripts. Remote execution
of those new targets remains unqualified until the same activation prerequisites
are satisfied; generated-declaration diagnostics do not replace that receipt.

Follow-up diagnostics on 2026-09-20: the exact released schema accepts the
expanded test action, and five contract cases plus six existing authority cases
pass. TypeScript 5.9.3 (the declared Bazel compiler version) emitted actual auth
declarations into a new temporary directory; the existing invitation guard
accepted that generated surface and rejected an injected executable invitation
export. The unchanged metadata guard accepted source version `0.7.1` and
rejected a deliberately mismatched tag. BUILD parsing and whitespace checks
pass. No local output is offered as remote qualification or a release artifact.

The 2026-09-21 TIN-89 retirement and new artifact/runfiles checks have not been
executed locally. Earlier passing results are historical to their named
preparation steps, not evidence for this changed source. Exact released-schema
validation, graph tests and source-bound lock verification remain outstanding;
no lock bytes or digests were edited as part of this retirement.
