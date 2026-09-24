# Bootstrap a consuming SvelteKit app from zero

This is the missing "from nothing" adoption guide for `@tummycrypt/tinyland-auth`.
It takes a brand-new SvelteKit app and wires it up to a working house-native
password plus TOTP login with a first `super_admin`, using only the public
`0.7.1` API.

Everything below is grounded in the reviewed `0.7.1` source. Each API is cited to
its source file at the end (see "Provenance"). Where a snippet fills an
integration seam that the package does not itself export, it is labelled
`ILLUSTRATIVE` so you can tell verified package API from glue you supply.

Pin `0.7.1` from the configured package authority. This guide is written
against that exact release.

## What you get

- A pluggable storage adapter holding users, sessions, TOTP secrets, backup
  codes, and audit events (built-in memory or file adapter, or a separate
  Postgres/Redis adapter package).
- A `hooks.server.ts` chain that resolves the session cookie into
  `event.locals.session` / `event.locals.user` on every request, renews sessions
  near expiry, and stamps a hashed client IP.
- Password hashing (bcrypt) and replay-resistant TOTP verification.
- A first-run `super_admin` bootstrap, both as an operator seed script and as an
  in-app guided flow.
- CSRF double-submit protection and route guards.

## 0. Prerequisites

The package declares these engines and peer deps:

- Node `>=22`
- `@sveltejs/kit` `^2.0.0` (peer, optional)
- `svelte` `^5.0.0` (peer, optional)

A SvelteKit 2 + Svelte 5 consumer must resolve those versions through its
reviewed build graph and use its repo-managed entrypoints.

### A note on install authority

TIN-89/TIN-1629 supersede the earlier package-provider advice: Bzlmod plus the
append-only Tinyland BCR is the sole first-party delivery authority. Resolve
`tummycrypt_tinyland_auth` through `bazel_dep` and link its `//:pkg` with
`npm_link_package`. Neither npmjs nor GitHub Packages is a delivery/fallback
lane; a vendored copy is not package authority. This guide retains its exact
0.7.1 API examples, not the retired installation topology. The TypeScript
import specifier remains `@tummycrypt/tinyland-auth`.

## 1. Required env and secrets

| Variable | Required | Purpose |
| --- | --- | --- |
| `TOTP_ENCRYPTION_KEY` | Yes | Symmetric key used to encrypt TOTP secrets at rest (`scrypt` key derivation + AES-256-GCM). Use a long, high-entropy string (32+ chars). Losing or rotating it makes every stored TOTP secret undecryptable. |
| `AUTH_DATA_DIR` | Only for the file adapter | Directory the `FileStorageAdapter` writes auth JSON under. Not needed for the memory adapter or a Postgres/Redis adapter. |
| `DATABASE_URL` | Only for `tinyland-auth-pg` | Postgres connection string, if you choose the Postgres adapter package instead of the built-in adapters. |

Never commit these. Load them from your platform's secret store or a local
`.env` that is gitignored.

The `TOTP_ENCRYPTION_KEY` is consumed as `TOTPServiceConfig.encryptionKey`.

## 2. Pick a storage adapter

`tinyland-auth` is storage-agnostic: it ships two built-in adapters and defers
durable backends to separate packages. All of them implement `IStorageAdapter`.

- `MemoryStorageAdapter` - in-process, non-durable. Perfect for tests and first
  boot. Everything is lost on restart.
- `FileStorageAdapter` (`createFileStorageAdapter`) - JSON-on-disk. Durable for a
  single-node app. Config fields: `authDir` (default `content/auth`), `totpDir`
  (default `.totp-secrets`), `sessionMaxAge`.
- `@tummycrypt/tinyland-auth-pg` / `@tummycrypt/tinyland-auth-redis` - separate
  packages for Postgres and Upstash Redis.

Start with the file adapter for a real single-node app:

```ts
// src/lib/server/storage.ts
import { createFileStorageAdapter } from '@tummycrypt/tinyland-auth/storage';

export const storage = createFileStorageAdapter({
  authDir: process.env.AUTH_DATA_DIR ?? 'content/auth',
});

// Call once at startup before first use.
await storage.init();
```

`init()` is part of the adapter lifecycle and must run before the adapter is
used (the shipped example calls `await storage.init()` right after
construction).

## 3. Central auth config and singletons

Create one module that builds the config once and constructs the long-lived
services. `createAuthConfig(overrides)` deep-merges your overrides over
`DEFAULT_AUTH_CONFIG`, so you only specify what differs.

```ts
// src/lib/server/auth.ts
import {
  createAuthConfig,
  createSessionManager,
  TOTPService,
} from '@tummycrypt/tinyland-auth';
import { storage } from './storage.js';

const encryptionKey = process.env.TOTP_ENCRYPTION_KEY;
if (!encryptionKey) {
  throw new Error('TOTP_ENCRYPTION_KEY is required');
}

export const authConfig = createAuthConfig({
  appName: 'My App',
  appUrl: process.env.PUBLIC_APP_URL ?? 'http://localhost:5173',
  session: {
    cookieName: 'sessionId',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    renewThreshold: 24 * 60 * 60 * 1000,
    maxConcurrentSessions: 5,
    // secureCookie defaults to true; keep it true in production.
  },
});

// createSessionManager takes (storage, sessionConfig).
export const sessions = createSessionManager(storage, authConfig.session);

// TOTPService takes { encryptionKey, issuer }.
export const totp = new TOTPService({
  encryptionKey,
  issuer: authConfig.appName,
});
```

`DEFAULT_AUTH_CONFIG` ships sensible defaults: session `cookieName: 'sessionId'`,
`maxAge` 7 days, `renewThreshold` 24h, `secureCookie: true`, `sameSite: 'lax'`,
password `minLength: 12` with complexity on, `bcryptRounds: 12`, TOTP
`issuer: 'Tinyland.dev'`, `digits: 6`, `period: 30`, `window: 1`. Override only
what you need.

## 4. Type your locals

The auth hook writes `session`, `user`, `clientIp`, `clientIpMasked`, and
`userAgent` onto `event.locals`. Declare them so the rest of your app is typed:

```ts
// src/app.d.ts
import type { Session, AdminUser } from '@tummycrypt/tinyland-auth/types';

declare global {
  namespace App {
    interface Locals {
      session: Session | null;
      user: AdminUser | null;
      clientIp: string;
      clientIpMasked: string;
      userAgent: string;
    }
  }
}

export {};
```

## 5. Wire hooks.server.ts

The SvelteKit adapter (`@tummycrypt/tinyland-auth/sveltekit`) provides
`createAuthHandle`, `createCSRFHandle`, and a `sequence` helper. `createAuthHandle`
resolves the session cookie, loads the user via your `loadUser` callback, renews
the session when `shouldRenewSession` says so, and populates `event.locals`.

```ts
// src/hooks.server.ts
import type { Handle } from '@sveltejs/kit';
import { redirect } from '@sveltejs/kit';
import {
  createAuthHandle,
  createCSRFHandle,
  sequence,
} from '@tummycrypt/tinyland-auth/sveltekit';
import { authConfig, sessions } from '$lib/server/auth.js';
import { storage } from '$lib/server/storage.js';

// 1. Resolve session + user into event.locals on every request.
const authHandle = createAuthHandle({
  sessionManager: sessions,
  config: authConfig,
  loadUser: (userId) => storage.getUser(userId),
  skipRoutes: ['/api/health', '/favicon.ico'],
});

// 2. Deny-by-default gate. Everything except public routes needs a session.
//    ILLUSTRATIVE: this small gate is app policy, not a package export. The
//    package ships per-route guards (requireAuth / requireRole) you can use
//    instead; this hook-level version mirrors the dollhouse-farm reference app.
const PUBLIC_ROUTES = ['/login', '/logout', '/api/health'];
const guardHandle: Handle = async ({ event, resolve }) => {
  const path = event.url.pathname;
  const isPublic = PUBLIC_ROUTES.some((r) => path === r || path.startsWith(r + '/'));
  if (!isPublic && !event.locals.session) {
    throw redirect(303, `/login?returnUrl=${encodeURIComponent(path)}`);
  }
  return resolve(event);
};

// 3. CSRF double-submit. Skip safe methods and the login/logout entry points.
const csrfHandle = createCSRFHandle({
  skipRoutes: ['/login', '/logout'],
});

export const handle = sequence(authHandle, guardHandle, csrfHandle);
```

`sequence` here is the package's own export (do not confuse it with
`@sveltejs/kit/hooks` `sequence`; either works, but the package ships its own).
The auth hook degrades to logged-out rather than throwing if the session cannot
be resolved, so a misconfigured secret yields a login redirect, not a 500.

## 6. First super_admin bootstrap (operator seed script)

This is the "from nothing" moment: the store has zero users and you need the
first `super_admin`. The most direct, fully public-API path is a one-shot seed
script the operator runs once. It mirrors the operations in the shipped
`examples/tinyland-databaseless-auth-mvp.ts`.

```ts
// scripts/auth-seed.ts  (run with: node --env-file=.env scripts/auth-seed.ts)
import {
  hashPassword,
  generateBackupCodes,
  createBackupCodeSet,
} from '@tummycrypt/tinyland-auth';
import { AdminRole } from '@tummycrypt/tinyland-auth/types';
import { createFileStorageAdapter } from '@tummycrypt/tinyland-auth/storage';
import { TOTPService } from '@tummycrypt/tinyland-auth/totp';

const HANDLE = process.env.SEED_HANDLE ?? 'admin';
const PASSWORD = process.env.SEED_PASSWORD; // supply via env, do not hardcode

async function main() {
  if (!PASSWORD) throw new Error('SEED_PASSWORD required');
  const encryptionKey = process.env.TOTP_ENCRYPTION_KEY;
  if (!encryptionKey) throw new Error('TOTP_ENCRYPTION_KEY required');

  const storage = createFileStorageAdapter({
    authDir: process.env.AUTH_DATA_DIR ?? 'content/auth',
  });
  await storage.init();

  if (await storage.hasUsers()) {
    throw new Error('Refusing to seed: users already exist');
  }

  const totp = new TOTPService({ encryptionKey, issuer: 'My App' });

  // 1. Create the super_admin user.
  const now = new Date().toISOString();
  const passwordHash = await hashPassword(PASSWORD, { rounds: 12 });
  const user = await storage.createUser({
    handle: HANDLE,
    displayName: HANDLE,
    passwordHash,
    role: AdminRole.SUPER_ADMIN,
    isActive: true,
    totpEnabled: true,
    needsOnboarding: false,
    onboardingStep: 0,
    createdAt: now,
    updatedAt: now,
  });

  // 2. Generate + store the TOTP secret (encrypted at rest).
  const secret = await totp.generateSecret(user.handle);
  const enc = totp.encrypt(secret.secret);
  await storage.saveTOTPSecret(user.handle, {
    userId: user.id,
    handle: user.handle,
    encryptedSecret: enc.encrypted, // EncryptedData.encrypted -> encryptedSecret
    iv: enc.iv,
    authTag: enc.tag,             // EncryptedData.tag -> authTag
    salt: enc.salt,
    createdAt: now,
    backupCodesGenerated: true,
    version: 1,
  });

  // 3. Generate + store backup codes. Print the plaintext once.
  const plainCodes = generateBackupCodes(10);
  const codeSet = createBackupCodeSet(user.id, plainCodes);
  await storage.saveBackupCodes(user.id, codeSet);

  // 4. Show the operator what to scan / save. secret.qrCodeUrl is a data: URL.
  console.log('super_admin created:', user.handle);
  console.log('Scan this TOTP secret in your authenticator app:');
  console.log('  otpauth secret:', secret.secret);
  console.log('  qr (data url):', secret.qrCodeUrl);
  console.log('Backup codes (store now, shown once):');
  for (const c of plainCodes) console.log('  ', c);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

Note the field mapping when persisting the secret: `TOTPService.encrypt()`
returns `EncryptedData` with `{ encrypted, salt, iv, tag }`, while the stored
`EncryptedTOTPSecret` shape uses `{ encryptedSecret, iv, authTag, salt }`. Map
`encrypted -> encryptedSecret` and `tag -> authTag`. This exact mapping appears
in the shipped example.

After this runs once, the operator has a working `super_admin` with password and
a TOTP secret in their authenticator app, plus one-time backup codes.

## 7. Login route (password + replay-resistant TOTP)

Login is two factors. Verify the password against the stored hash, then verify
the TOTP code. Since `0.6.0`, use `verifyTokenWithStep`, which rejects replay of a
still-valid code by comparing the consumed time-step against the last one you
persisted.

```ts
// src/routes/login/+page.server.ts
import { fail, redirect } from '@sveltejs/kit';
import { verifyPassword } from '@tummycrypt/tinyland-auth';
import type { TOTPSecret } from '@tummycrypt/tinyland-auth/types';
import { setSessionCookie } from '@tummycrypt/tinyland-auth/sveltekit';
import { sessions, totp, authConfig } from '$lib/server/auth.js';
import { storage } from '$lib/server/storage.js';

export const actions = {
  default: async ({ request, cookies, getClientAddress }) => {
    const form = await request.formData();
    const handle = String(form.get('handle') ?? '');
    const password = String(form.get('password') ?? '');
    const code = String(form.get('totp') ?? '');

    const user = await storage.getUserByHandle(handle);
    if (!user || !user.isActive) return fail(401, { error: 'Invalid credentials' });

    // Factor 1: password.
    const okPassword = await verifyPassword(password, user.passwordHash);
    if (!okPassword) return fail(401, { error: 'Invalid credentials' });

    // Factor 2: TOTP with replay protection.
    const stored = await storage.getTOTPSecret(user.handle);
    if (!stored) return fail(401, { error: 'TOTP not enrolled' });

    const plainSecret = totp.decrypt({
      encrypted: stored.encryptedSecret,
      salt: stored.salt,
      iv: stored.iv,
      tag: stored.authTag,
    });
    const secret: TOTPSecret = {
      handle: user.handle,
      secret: plainSecret,
      createdAt: new Date(),
    };

    const result = await totp.verifyTokenWithStep(secret, code, stored.lastUsedTotpStep);
    if (!result.valid) return fail(401, { error: 'Invalid or reused code' });

    // Persist the consumed step so the same code cannot be replayed.
    // ILLUSTRATIVE: re-save the record with the new lastUsedTotpStep. Use
    // whatever update path your adapter exposes; saveTOTPSecret overwrites by
    // handle in the built-in adapters.
    await storage.saveTOTPSecret(user.handle, {
      ...stored,
      lastUsedTotpStep: result.step,
    });

    // Mint the session and set the cookie.
    const session = await sessions.createSession(user.id, user, {
      clientIp: getClientAddress(),
      clientIpMasked: getClientAddress(),
      userAgent: request.headers.get('user-agent') ?? 'unknown',
      deviceType: 'desktop',
    });
    setSessionCookie(cookies, session.id, {
      sessionCookieName: authConfig.session.cookieName,
      secure: authConfig.session.secureCookie,
      maxAge: Math.floor(authConfig.session.maxAge / 1000),
    });

    throw redirect(303, '/');
  },
};
```

`verifyTokenWithStep` returns `{ valid, step? }`. On success, `step` is the
newly-consumed time-step; persist it into `lastUsedTotpStep` and feed it back on
the next verification. The legacy boolean `verifyToken(secret, code)` still
exists as a stateless migration path if you do not want replay tracking yet.

To log out, clear the cookies and remove the session:

```ts
// src/routes/logout/+page.server.ts (action)
import { clearSessionCookies } from '@tummycrypt/tinyland-auth/sveltekit';
import { sessions } from '$lib/server/auth.js';

// inside the action:
if (locals.session) await sessions.removeSession(locals.session.id);
clearSessionCookies(cookies);
```

## 8. Enroll TOTP for a user who does not have it yet

The seed script enrolls the first admin. For later users (or a user who skipped
it), the enroll flow is: generate a secret, show the QR, verify one code from
the authenticator, then persist the encrypted secret and flip `totpEnabled`.

```ts
// generate + show (server load or action)
const secret = await totp.generateSecret(user.handle); // secret.qrCodeUrl is a data: URL to render
// keep secret.secret server-side (e.g. short-lived signed state) until verified

// verify the first code before saving
const ok = await totp.verifyToken(
  { handle: user.handle, secret: pendingSecret, createdAt: new Date() },
  submittedCode,
);
if (ok) {
  const enc = totp.encrypt(pendingSecret);
  await storage.saveTOTPSecret(user.handle, {
    userId: user.id,
    handle: user.handle,
    encryptedSecret: enc.encrypted,
    iv: enc.iv,
    authTag: enc.tag,
    salt: enc.salt,
    createdAt: new Date().toISOString(),
    backupCodesGenerated: false,
    version: 1,
  });
  // then mark user.totpEnabled = true via your adapter's user update path
}
```

## 9. Optional: in-app guided bootstrap with BootstrapService

If you prefer a guided `/bootstrap` route over a seed script, the package ships
`BootstrapService` (`createBootstrapService`). It enforces the "no users yet"
precondition, validates the handle, and its `complete()` step hardcodes
`role: 'super_admin'`, so it is purpose-built for the first admin. Its config
takes callbacks for the TOTP primitives:

```ts
import { createBootstrapService } from '@tummycrypt/tinyland-auth';
import {
  generateTOTPSecret,
  generateTOTPUri,
  generateTOTPQRCode,
} from '@tummycrypt/tinyland-auth/totp';
import { totp } from '$lib/server/auth.js';
import { storage } from '$lib/server/storage.js';

const bootstrap = createBootstrapService({
  storage,                       // needs hasUsers/createUser/saveTOTPSecret/getTOTPSecret/saveBackupCodes/logAuditEvent
  appName: 'My App',
  bcryptRounds: 12,
  backupCodesCount: 10,
  generateTOTPSecret,            // () => string (base32 secret)
  generateQRCode: (handle, secret, issuer) =>
    generateTOTPQRCode(generateTOTPUri(secret, issuer, handle)), // () => Promise<data-url>
  encryptTOTPSecret: async (handle, secret) => {
    const enc = totp.encrypt(secret);
    return {
      userId: 'pending',         // placeholder; record is keyed by handle (complete() does not backfill this)
      handle,
      encryptedSecret: enc.encrypted,
      iv: enc.iv,
      authTag: enc.tag,
      salt: enc.salt,
      createdAt: new Date().toISOString(),
      backupCodesGenerated: true,
      version: 1,
    };
  },
  // verifyTOTP: (secret: string, token: string) => boolean
  // ILLUSTRATIVE seam: the package does not export a synchronous string-based
  // TOTP verifier, and this callback must be synchronous (complete() calls it
  // without awaiting). Supply one using otplib, which tinyland-auth itself
  // depends on internally, configured to match the package (step 30, window 1,
  // SHA1, 6 digits). If you cannot add that verifier, prefer the seed script in
  // section 6, which needs no in-app code round-trip.
  verifyTOTP: (secret, token) => {
    // e.g. otplib authenticator.check(token, secret) with matching options
    throw new Error('supply a synchronous TOTP verifier');
  },
});
```

Flow: `getStatus()` tells you whether bootstrap is still allowed
(`needsBootstrap`); `initiate({ handle, password, displayName, email? })` returns
`{ state, qrCodeUrl, backupCodes }` (you carry `state` from `initiate` into
`complete` yourself); `complete(state, { handle, totpCode })` verifies the
code, writes the `super_admin`, stores backup codes, logs a
`BOOTSTRAP_COMPLETED` audit event, and returns the safe user. The state expires
10 minutes after `initiate`.

Protect `state` in transit. `BootstrapState` is a plain object that holds a raw
(unencrypted) TOTP secret, the bcrypt password hash, and the plaintext backup
codes. This legacy service does not sign, encrypt, or serialize it for you.
A signed/httpOnly cookie is NOT confidential: do not put this state in browser
custody. It also has no durable multi-record completion journal. Use the opt-in
coordinator below when crash-safe server-held setup is required.

The seed script in section 6 is the lower-friction path for most apps; reach for
`BootstrapService` when you want the whole thing to happen inside the running app
with no shell access.

### Encrypted durable file bootstrap (unreleased candidate)

`FileBootstrapCoordinator` from `@tummycrypt/tinyland-auth/storage` adds an
explicit, opt-in file transaction. It does not change `BootstrapService`, open
bootstrap on an installed system, or migrate/modify existing administrators.
With no journal, `recover()` performs no writes, including no directory creation.

Configure `directory`, a stable deployment/tenant `scope`, the existing
configured `TOTPService`, raw `storage` reads (`getAllUsers`, `getTOTPSecret`,
`getBackupCodes`), `withExclusiveAuth`, and an idempotent `project` callback.
The encryption key must have durable operator custody before use; do not supply
a development fallback. Encryption uses the existing scrypt/AES-256-GCM
configuration. Every payload includes a bootstrap-specific domain, versioned
schema and deployment scope INSIDE its authenticated ciphertext. Plaintext
headers are only envelope version and encryption parameters. No new database
or general-purpose browser claim store is introduced.

API:

- `begin({ handle, passwordHash, profile? })` reserves one empty installation
  and returns setup material plus a random 256-bit `reference`. New handles are
  trimmed/lowercased and must match `[a-z0-9][a-z0-9_-]{2,29}` (3–30 characters).
  The returned effective handle is used for every frozen owner/factor/profile
  identity; existing users and authenticated journal records are never renamed.
- `read(reference)` resumes the SAME attempt after restart, only while it is
  unexpired, correctly bound, and the installation is still empty.
- `updateProfile(reference, profile)` changes only bounded profile metadata;
  it never changes the user ID, factor, reference or original expiry.
- `acknowledgeBackupCodes(reference)` durably records an explicit server action
  acknowledging THIS pending attempt's codes. `BootstrapSetup` exposes
  `backupCodesAcknowledged` for resumed UI state. Completion is denied before
  token verification until acknowledged; a new/replacement attempt starts false.
- `complete({ reference, token })` verifies the factor with its consumed TOTP
  step, durably commits frozen completion material, projects it and returns a
  safe historical receipt. It never returns a user/session or issues a login.
- `recover()` finishes committed projection without an unexpired browser
  reference; it does not disclose setup, raw factor, password hash or codes.
- `assertAvailable()` rejects existing users, live pending reservations and
  the permanent applied latch. Alternative initialization MUST hold the same
  external auth gate across this check AND all its writes; calling this method
  alone and later creating a user outside the gate is not safe.

Only the opaque `reference` belongs in the httpOnly, strict-same-site setup
cookie. It is a temporary setup capability, not a user/session credential. The
journal persists its domain-separated digest, never the reference itself.
The whole pending record is encrypted, including password hash, TOTP secret,
plaintext recovery codes and profile. Pending TTL is absolute, positive and at
most ten minutes; no read/profile update extends it. Expired pending may be
replaced only with no users and no conflicting candidate factor/recovery state.
Old references cannot adopt replacements. Applied completion stays latched even
if all users are subsequently removed; normal removal is not rebootstrap consent.

The coordinator requires the application's SHARED reentrant single-process
auth gate. Do not use a no-op gate or an independent bootstrap-only mutex.
Use the same gate for user/invitation creation, OAuth initialization, password
changes and other auth writes. Run bootstrap recovery before route/bootstrap
existence checks, sessions, invitations or other auth traffic. The canonical
enrollment coordinator's `withReadyAuth` can provide this gate; app readiness
can then recover bootstrap and invitation journals inside it. Projection uses
raw adapters, never gated entrypoints. Multi-pod/distributed locking is NOT
provided. Namespace/scope and gate identity must remain stable across restarts.

Apps with user-owned content supply the optional trusted
`assertNamespaceAvailable(handle): Promise<void>` callback. It runs under that
same gate before new material generation, before publishing pending, and
immediately before commit. Reject any existing namespace path (directory, file
or symlink), including retained content whose user has been removed; never adopt
it just because the user store is empty. Callback failures are generic conflicts
and cannot leak private paths. The callback is read-only and must not reenter
the gate. It does NOT run during committed recovery: the idempotent projection
must instead validate and finish only its exact frozen owned content. A shared
gate protects cooperating app writers, not independent external filesystem edits.

The backup acknowledgment action must be an actual validated POST (and bound to
the opaque reference), not a client-only checkbox or navigation link. Visiting
the final step or submitting its token directly cannot substitute for the
durable acknowledgment. Profile updates and restarts preserve it without
extending TTL; invalid/expired/other-attempt references cannot acknowledge it.

Each write uses a private (0700) directory, an exclusive 0600 temporary file,
file fsync, atomic rename and directory fsync. Newly created directory entries
are synced through their existing parent. Pending is durable before any setup
material returns. Empty-user/factor authority and expiry are rechecked after
asynchronous generation, verification and pending publication. Commit freezes
one explicit user ID, the consumed factor step, backup hashes, profile and a
canonical material digest BEFORE any projection. A crash after committed
rename, including an uncertain directory sync, is repaired before auth resumes.
Incorrect key/scope, malformed/unknown versions, conflicting live records and
projection failures keep recovery closed; there is no plaintext/legacy fallback.

Projection must preserve frozen identity and detect conflicting user, factor,
backup and profile data. Write factor and backup hashes and the optional profile
BEFORE creating the user, using the explicit completion user ID. Do not overwrite
an existing profile or matching user's subsequently changed credentials, grants,
flags or factor state. Preserve used backup codes and monotonic factor counters
on partial replay. An identical already-published user can finish an interrupted
transaction; another owner, removed marker or changed immutable identity cannot.
Never delete partial records as rollback. Once applied, recovery does not project
again, so later authorized account changes are untouched. Receipts describe a
historical operation, not current factor/account status.

Migration is source-only until explicitly activated: reject old secret-bearing
bootstrap cookies rather than importing their browser claims. Empty installations
can start a fresh attempt; existing users remain unchanged. GitHub or other
first-run creation must either join this authority or be explicitly held closed;
ordinary linked-account login is a separate flow and must remain available.
Never infer provider MFA merely from a successful OAuth exchange.

The first pending journal write is a rollback barrier. An older application
that ignores this journal can create a competing administrator or miss recovery.
Retain a journal-aware reader/projector in rollback images, or explicitly use
roll-forward recovery. Retain the key and scope with durable storage backups;
do not erase/downgrade journals or restore stale factor/user files to boot an old
image. No state migration, runtime initialization or publication is performed by
adding these source APIs.

## 10. Minimum viable checklist

1. `TOTP_ENCRYPTION_KEY` set (32+ chars, secret, stable).
2. A storage adapter constructed and `init()`ed (`FileStorageAdapter` to start).
3. `src/lib/server/auth.ts` building `createAuthConfig`, `createSessionManager`,
   and `TOTPService`.
4. `src/app.d.ts` declaring the five locals the hook writes.
5. `src/hooks.server.ts` running `sequence(authHandle, guardHandle, csrfHandle)`.
6. First `super_admin` seeded once (section 6) or bootstrapped in-app (section 9).
7. A `/login` action verifying password + TOTP and calling `setSessionCookie`.

At that point an unauthenticated request to any non-public route redirects to
`/login`, and a correct password plus TOTP code mints a session.

## Provenance (0.7.1 source)

Every API named above is a public export of `@tummycrypt/tinyland-auth@0.7.1`.
Verified against the release source:

- Root exports (`hashPassword`, `verifyPassword`, `validatePassword`,
  `generateBackupCodes`, `createBackupCodeSet`, `verifyBackupCode`,
  `createAuthConfig`, `DEFAULT_AUTH_CONFIG`, `TOTPService`, `createTOTPService`,
  `createSessionManager`, `SessionManager`, `MemoryStorageAdapter`,
  `FileStorageAdapter`, `createFileStorageAdapter`, `createBootstrapService`,
  `BootstrapService`, `hashIp`, `maskIp`): `src/index.ts`.
- SvelteKit adapter (`createAuthHandle`, `createCSRFHandle`, `sequence`,
  `getClientIp`, `requireAuth`, `requireRole`, `requirePermission`,
  `setSessionCookie`, `clearSessionCookies`, `getSessionIdFromCookies`):
  `src/adapters/sveltekit/{index,hook,guards,session-cookies}.ts`.
- `TOTPService` methods (`generateSecret`, `generateToken`, `verifyToken`,
  `verifyTokenWithStep`, `encrypt`, `decrypt`) and `TOTPServiceConfig`:
  `src/core/totp/index.ts`. `verifyTokenWithStep` and the
  `EncryptedTOTPSecret.lastUsedTotpStep` field are the `0.6.0` replay-protection
  additions (TIN-2667).
- `./totp` compat helpers (`generateTOTPSecret`, `generateTOTPUri`,
  `generateTOTPQRCode`, `generateTOTPToken`): `src/totp/compat.ts`.
- `SessionManager` (`createSession`, `getSession`, `validateSession`,
  `refreshSession`, `removeSession`, `shouldRenewSession`) and
  `createSessionManager(storage, sessionConfig)`: `src/core/session/index.ts`.
- Storage interface (`IStorageAdapter`, `BootstrapStorage`, `createUser`,
  `hasUsers`, `getUser`, `getUserByHandle`, `saveTOTPSecret`, `getTOTPSecret`,
  `saveBackupCodes`, `logAuditEvent`): `src/storage/interface.ts`,
  `src/storage/{memory,file}.ts`.
- `FileStorageConfig` (`authDir`, `totpDir`, `sessionMaxAge`):
  `src/storage/file.ts`.
- `BootstrapService` config and `complete()` writing `role: 'super_admin'`:
  `src/modules/bootstrap/index.ts`.
- `DEFAULT_AUTH_CONFIG` values (session `cookieName: 'sessionId'`, `maxAge` 7d,
  `renewThreshold` 24h, password `minLength: 12`, TOTP `issuer`, `digits: 6`,
  `period: 30`, `window: 1`): `src/types/config.ts`.
- `AdminRole` value map (`AdminRole.SUPER_ADMIN === 'super_admin'`),
  `EncryptedTOTPSecret`, `AdminUser`, `Session`, `TOTPSecret`, `EncryptedData`
  types: `src/types/auth.ts`.
- End-to-end reference for the create-user + encrypt + save-TOTP + backup-codes
  sequence: `examples/tinyland-databaseless-auth-mvp.ts`.

Snippets labelled `ILLUSTRATIVE` fill integration seams (a deny-by-default hook,
persisting `lastUsedTotpStep`, and a synchronous TOTP verifier for
`BootstrapService`) that are app policy or supplied glue rather than package
exports. Everything else is verified `0.7.1` API.
