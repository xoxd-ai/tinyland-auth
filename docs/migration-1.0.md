# Migrating to @tummycrypt/tinyland-auth 1.0.0

1.0.0 removes the fixed-code TOTP bypass and every test seam from the
production entry points (ruling RS6). It also moves the test harness behind a
hard gate that keeps it out of the published package (ruling RS5). Carrier:
TIN-5766. The consumer audit for this change is W3-audit (2026-10-07).

## What to change

| If your code... | Then... |
| --- | --- |
| passes `devMode` to `new TOTPService({...})` or `createTOTPService` | Delete the key. With no `testCode` it never did anything, and in 1.0.0 the bypass is gone. |
| passes `testCode` | Delete it. Tests must produce a real TOTP code from the stored secret (`TOTPService.generateToken`). |
| sets `devMode` in a `TOTPConfig` object or a copy of `DEFAULT_AUTH_CONFIG.totp` | Delete the field. Spreading `DEFAULT_AUTH_CONFIG.totp` still compiles. |
| imported `TotpVerifier`, `otplibTotpVerifier`, `Clock`, `systemClock` or `BackupCodeGenerator` | These were never in a published release. Remove the import. |
| imported `@tummycrypt/tinyland-auth/testing` | It is not published. Drive the real journeys, or run the package's own tests from this repo. |

No runtime behaviour changes for a consumer that did not set `testCode`.

## Known consumers (audit 2026-10-07)

- **xoxd-ai/tinyland.dev**:
  - Delete `devMode: process.env.NODE_ENV === 'development'` from
    `src/lib/server/auth/totp-service.ts`, and the app-local `totp.devMode`
    type and default from `src/lib/types/auth.ts`.
  - Re-pin with `just sync-pull tinyland-auth`, and bump `bazel_dep` and
    `single_version_override` to 1.0.0.
  - Widen the in-repo `tinyland-admin-validation` and `tinyland-security` peer
    ranges to include `^1.0.0`.
  - Keep the auth-e2e forbidden markers for the testing subpath.
- **euthanasiapettingparts.com, software.tinyland.dev-booking,
  elders.tinyland.dev, dollhouse-farm**: they stay on 0.3.x for now. None of
  them sets `devMode` or `testCode`. Moving to 1.0.0 also crosses the 0.4 to
  0.7 changes and needs the `tinyland-auth-pg` peer range widened first.
  `dollhouse-farm` must redo its Bazel patch against 1.0.0.
- **tinyland-auth-pg, tinyland-auth-redis, tinyland-security,
  tinyland-admin-validation**: widen the `@tummycrypt/tinyland-auth` peer
  range to include `^1.0.0` when the apps re-pin.

## Release

Tag `v1.0.0` from `main` after merge and add
`tummycrypt_tinyland_auth/1.0.0` to the Tinyland Bazel registry. 0.7.1 is not
yanked: its bypass works only if the caller sets `testCode`, and no audited
consumer does.
