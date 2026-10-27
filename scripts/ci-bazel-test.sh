#!/usr/bin/env bash
set -euo pipefail

# Local, non-qualifying (TIN-5770, R471): no GF lane admits these targets yet.
# Prefer the devshell launcher. The npx fallback is pinned. Each call runs with
# --batch, so the script leaves no Bazel server behind (R472).
if command -v bazelisk >/dev/null 2>&1; then
  bazel=(bazelisk)
elif command -v bazel >/dev/null 2>&1; then
  bazel=(bazel)
else
  bazel=(npx --yes @bazel/bazelisk@1.28.1)
fi
printf 'Bazel: local, non-qualifying (%s --batch)\n' "${bazel[*]}"

printf 'Executing Bazel tests: //:test (and building //:typecheck)\n'
"${bazel[@]}" --batch test //:test //:typecheck --test_output=errors

# RS5 / RS6: the production-exclusion proof against the published //:pkg.
printf 'Executing Bazel test: //:production_artifact_test\n'
"${bazel[@]}" --batch test //:production_artifact_test --test_output=errors

# RS6 / RP2: the ./storage coordinators verify TOTP codes themselves, proven on //:pkg.
printf 'Executing Bazel test: //:totp_authority_artifact_test\n'
"${bazel[@]}" --batch test //:totp_authority_artifact_test --test_output=errors

# TIN-4435/AP3: the canonical-source qualification targets the tinyland.dev
# candidate-image publisher expects. Run here so a broken target goes red in CI.
printf 'Executing Bazel tests: qualification targets\n'
"${bazel[@]}" --batch test //:release_metadata_test //:invitation_authority_test //:package_artifact_test --test_output=errors
