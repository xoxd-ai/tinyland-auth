# Bazel registry wiring for `@tummycrypt/tinyland-auth`

> **DRAFT — for operator review, not yet ratified.** (2026-07-11)
> This document declares one internally-contradicting pattern "blessed" based
> on reading `tinyland.dev`'s own `github/main` source, not on an existing
> operator ADR. Treat it as a strong recommendation pending sign-off, not a
> settled org policy.

## The contradiction this doc resolves

Two different Bazel registry-wiring patterns exist across Tinyland repos that
consume this package:

1. **Per-module override (this doc's recommendation)** — `tinyland.dev`
   (`github/main`, verified at commit `98c619f`, `.bazelrc:15` and
   `MODULE.bazel:77,176-180`): `.bazelrc` sets only
   `common --registry=https://bcr.bazel.build`. Each Tinyland-authored module
   gets an explicit `single_version_override(module_name=..., registry=
   TINYLAND_BAZEL_REGISTRY, version=...)` next to its `bazel_dep`.
2. **Global search-path override (deprecated, DRAFT-discouraged)** —
   `elders.tinyland.dev` (`origin/main`, and by extension
   `massage-ithaca-portal`, `scheduling-bridge`, `scheduling-kit`,
   `tinyland-security`, `tinyland-admin-validation`): `.bazelrc` adds
   `common --registry=https://raw.githubusercontent.com/tinyland-inc/bazel-registry/main/`
   as a global search path ahead of `bcr.bazel.build`, then a plain
   `bazel_dep(name = "tummycrypt_tinyland_auth", version = "0.3.0")` with no
   override.

`tinyland.dev`'s own comment in `.bazelrc` explains the reasoning: "Promoted
Tinyland package modules use per-module registry overrides in MODULE.bazel so
fallback probes stay narrow." A global registry search path means *every*
module resolution — including third-party BCR modules that happen to share a
name — probes the org registry first. A per-module override only redirects
the specific modules Tinyland actually publishes.

This doc picks pattern 1 because it is what the actual production consumer
(`tinyland.dev`, `github/main`) does today. **It does not resolve whether the
other repos on pattern 2 should migrate** — that is a separate,
operator-scheduled cleanup, out of scope here.

## The blessed recipe

For a fresh Bazel-first app adopting `@tummycrypt/tinyland-auth`:

**`.bazelrc`** — no org registry entry:

```
common --registry=https://bcr.bazel.build
```

**`MODULE.bazel`** — declare the dependency, then pin it explicitly to the
Tinyland registry with a matching version on both lines:

```python
TINYLAND_BAZEL_REGISTRY = "https://raw.githubusercontent.com/tinyland-inc/bazel-registry/main"

bazel_dep(name = "tummycrypt_tinyland_auth", version = "0.6.0")

single_version_override(
    module_name = "tummycrypt_tinyland_auth",
    registry = TINYLAND_BAZEL_REGISTRY,
    version = "0.6.0",
)
```

BCR (`bcr.bazel.build`) stays the default registry for everything else —
public/upstream rules (`aspect_rules_js`, `rules_nodejs`, etc.) resolve there
normally. The `single_version_override` only redirects the one module
Tinyland actually authors and publishes; it does not widen the search path
for anything else. Keep the version string identical between `bazel_dep` and
`single_version_override` — a mismatch here is exactly the kind of source
drift this doc is trying to prevent (see the sibling
`docs/invite-onboarding-walkthrough.md` for a live example of that failure
mode in a related package).

## Prior art in this org

`tinyland.dev`'s vendored `packages/tinyland-auth/MODULE.bazel` documents the
same intent for standalone consumption of this module and cites the same
resolution decision:

> As of #616 (TIN-1721 Stage 1), the root MODULE.bazel resolves this module
> via `single_version_override` against the org bazel-registry, not a
> `local_path_override` to this vendored copy.

## Out of scope

- This doc does not migrate or judge `elders.tinyland.dev`,
  `massage-ithaca-portal`, `scheduling-bridge`, `scheduling-kit`,
  `tinyland-security`, or `tinyland-admin-validation`. Their global-registry
  pattern keeps working as-is; changing it is a separate, operator-scheduled
  effort.
- This doc does not cover `pnpm`/npm-registry consumption. Per this repo's
  `README.md`, npmjs publication of `@tummycrypt/tinyland-auth` is disabled;
  Bazel-registry consumption is the current release authority for this repo.

## Provenance

- `tinyland.dev` `.bazelrc` (`common --registry=` line, comment):
  `github/main` at commit `98c619f954dc985d0aef42ce53a778f566d1f440`.
- `tinyland.dev` `MODULE.bazel` (`bazel_dep`, `TINYLAND_BAZEL_REGISTRY`,
  `single_version_override` for `tummycrypt_tinyland_auth`): same commit,
  lines 77 and 114/176-180.
- `tinyland.dev` `packages/tinyland-auth/MODULE.bazel` header comment
  (standalone-consumption prior art, TIN-1721 / #616): same commit.
- `elders.tinyland.dev` `.bazelrc` and `MODULE.bazel`
  (`tummycrypt_tinyland_auth` version `0.3.0`, no override): `origin/main`.
