#!/usr/bin/env bash
set -euo pipefail

printf 'Executing Bazel tests: //:test (and building //:typecheck)\n'
npx --yes @bazel/bazelisk test //:test //:typecheck --test_output=errors

# RS5 / RS6: the production-exclusion proof against the published //:pkg.
printf 'Executing Bazel test: //:production_artifact_test\n'
npx --yes @bazel/bazelisk test //:production_artifact_test --test_output=errors
