set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

[doc("Install JS dependencies")]
install:
    pnpm install --frozen-lockfile

[doc("Typecheck src and tests")]
typecheck:
    pnpm typecheck

[doc("Run the vitest suite")]
test:
    pnpm test

[doc("Build dist/")]
build:
    pnpm build

[doc("Local, non-qualifying (R471): the Bazel targets CI runs, one --batch call each")]
test-bazel:
    pnpm test:bazel

[doc("Routine gate: typecheck and vitest, no Bazel server")]
check: typecheck test
