# Bootstrap a consuming SvelteKit app from zero

This guide combines released `@tummycrypt/tinyland-auth@0.7.1` APIs with an
explicitly marked, source-only draft of the breaking 0.8 first-user bootstrap
contract. The draft sections are implementation guidance for this repository;
they are not an installable 0.8 release or an adoption claim.

Each API is cited to its source file at the end (see "Provenance"). Where a
snippet fills an
integration seam that the package does not itself export, it is labelled
`ILLUSTRATIVE` so you can tell verified package API from glue you supply.

Pin `0.7.1` for the released general-auth sections. The atomic storage and
guided bootstrap sections require a build from this unreleased 0.8 source and
must not be represented as available from `0.7.1` or from a published `0.8`.

## What you get

- A pluggable storage adapter holding users, sessions, TOTP secrets, backup
  codes, and audit events (built-in memory or file adapter, or a separate
  Postgres/Redis adapter package).
- A `hooks.server.ts` chain that resolves the session cookie into
  `event.locals.session` / `event.locals.user` on every request, renews sessions
  near expiry, and stamps a hashed client IP.
- Password hashing (bcrypt) and replay-resistant TOTP verification.
- In the unreleased 0.8 source only, a first-run `super_admin` bootstrap as an
  operator seed script or an in-app guided flow.
- CSRF double-submit protection and route guards.

## 0. Prerequisites

The package declares these engines and peer deps:

- Node `>=22`
- `@sveltejs/kit` `^2.0.0` (peer, optional)
- `svelte` `^5.0.0` (peer, optional)

A default `npm create svelte@latest` (SvelteKit 2 + Svelte 5) app satisfies
this.

### A note on install authority

Per the package README, Tinyland's current release authority for this repo is
Bazel-first, and npmjs publication is disabled. `pnpm add
@tummycrypt/tinyland-auth` is valid only against a registry configured to serve
the `@tummycrypt` scope; Bazel consumers should depend through the Tinyland
Bazel registry / BCR module path (`tummycrypt_tinyland_auth`) instead of a
workspace-local copy. This guide shows the import surface; how you make that
surface resolvable (registry npm, Bazel module graph, or vendored copy) is your
build's decision. The TypeScript import specifier is always
`@tummycrypt/tinyland-auth`.

## 1. Required env and secrets

| Variable | Required | Purpose |
| --- | --- | --- |
| `TOTP_ENCRYPTION_KEY` | Yes | Symmetric key used to encrypt TOTP secrets at rest (`scrypt` key derivation + AES-256-GCM). Use a long, high-entropy string (32+ chars). Losing or rotating it makes every stored TOTP secret undecryptable. |
| `AUTH_DATA_DIR` | Only for the file adapter | Durable root for ordinary auth records, encrypted factors, bootstrap receipts/locks, and the default encrypted operator packet. Persist the whole root atomically. |
| `AUTH_TENANT_ID` | For unreleased 0.8 bootstrap | Canonical UUID that scopes the bootstrap claim, finalization, receipt, and durable attempt custody. |
| `SEED_RECOVERY_KEY` | For the operator seed example | Stable 32+ character secret used to encrypt the restart packet before any claim or finalization. |
| `SEED_PACKET_PATH` | Optional for the operator seed example | Private durable path for the encrypted restart packet; defaults to `$AUTH_DATA_DIR/operator/auth-seed.packet`. |
| `DATABASE_URL` | Only for legacy `tinyland-auth-pg` operations | Postgres connection string for ordinary auth operations. The current PG adapter does not support atomic first-user bootstrap. |

Never commit these. Load them from your platform's secret store or a local
`.env` that is gitignored.

The `TOTP_ENCRYPTION_KEY` is consumed as `TOTPServiceConfig.encryptionKey`.

## 2. Pick a storage adapter

The released package is storage-agnostic: it ships two built-in adapters and
defers durable backends to separate packages. For the unreleased 0.8 atomic
bootstrap draft, support is narrower:

- `MemoryStorageAdapter` - in-process, non-durable. Perfect for tests and first
  boot. Everything is lost on restart.
- `FileStorageAdapter` (`createFileStorageAdapter`) - JSON-on-disk. Durable for a
  single-node app. Config fields: `authDir` (default `content/auth`), `totpDir`
  (default `.totp-secrets`), `sessionMaxAge`.
- `@tummycrypt/tinyland-auth-pg` / `@tummycrypt/tinyland-auth-redis` - legacy
  ordinary-auth adapters only. They do not implement the required native
  bootstrap claim/finalize/receipt transaction and are unsupported for the
  draft workflow until dedicated durable CAS implementations land and pass the
  public conformance runner.

Start with the file adapter for a real single-node app:

```ts
// src/lib/server/storage.ts
import { createFileStorageAdapter } from '@tummycrypt/tinyland-auth/storage';
import { join } from 'node:path';

const authRoot = process.env.AUTH_DATA_DIR ?? 'var/auth';
export const storage = createFileStorageAdapter({
  authDir: join(authRoot, 'records'),
  totpDir: join(authRoot, 'secrets'),
});

// Call once at startup before first use.
await storage.init();
```

`init()` is part of the adapter lifecycle and must run before the adapter is
used (the shipped example calls `await storage.init()` right after
construction).

Treat `AUTH_DATA_DIR` as one persistence unit. With the configuration above,
users/sessions/audit data live under `records/`; encrypted TOTP factors, backup
codes, tenant-bound receipts, and the two-slot lock live under `secrets/`; the
seed example below defaults its encrypted recovery packet under `operator/`.
The logical secret directory is the adapter's `totpDir`; `TOTPService` itself
does not write a separate `secretDir`. Back up and restore the complete root.

The two-slot lock keeps one fixed-size released owner set in steady state. Its
release publication never unlinks the current owner and performs no pathname
read or delete after the final marker. A normal active-owner timeout means
retry later. If timeouts persist after all known participants stop, liveness is
ambiguous on a shared filesystem and recovery must be attended: preserve the
lock and bootstrap record for diagnosis, verify no owner can still run, and
only then retire the lock directory. Never automate stale takeover while an
adapter may be active.

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

> **Unreleased 0.8 source only.** This protocol is implemented by the built-in
> memory/file adapters in this source tree. It is not part of released 0.7.1,
> and the current PostgreSQL/Redis adapters do not support it.

This is the "from nothing" moment: the store has zero users and you need the
first `super_admin`. Use the storage-level claim/finalize protocol so no active
user, credential, role, session authority, TOTP enrollment, or backup-code use
exists before one atomic finalization. The immutable completion receipt makes
an exact retry idempotent and rejects mismatched retries.

Claim acceptance revokes every session already in the built-in adapter's
single-tenant boundary and rejects new sessions until finalization. Afterward,
normal sessions can be created. Role and permission guards require the matching
storage-loaded `event.locals.user`; an embedded session role alone is not
privileged authority, which is why the `loadUser` callback in section 5 is
load-bearing.

A persisted 0.7 file store is a separate migration case: it has users but no
0.8 receipt and must not run the zero-user flow below. On its next ordinary
`createUser` (including invitation acceptance), the file adapter requires
exactly one active, unlocked `super_admin`, atomically records that user in an
immutable reconciliation marker under `totpDir`, and proceeds. Zero or multiple
eligible owners fail closed for operator repair. The marker preserves legacy
operation without pretending that a 0.8 claim/finalization receipt exists.

```ts
// scripts/auth-seed.ts  (run with: node --env-file=.env scripts/auth-seed.ts)
import {
  createBackupCodeSet,
  generateBackupCodes,
  hashPassword,
  type FirstUserBootstrapFinalization,
  type InertFirstUserClaim,
} from '@tummycrypt/tinyland-auth';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
} from 'node:crypto';
import { link, mkdir, open, readFile, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { stdin, stdout } from 'node:process';
import { createInterface } from 'node:readline/promises';
import { AdminRole } from '@tummycrypt/tinyland-auth/types';
import {
  createFileStorageAdapter,
  resolveAuthTenantId,
} from '@tummycrypt/tinyland-auth/storage';
import { TOTPService } from '@tummycrypt/tinyland-auth/totp';

const HANDLE = process.env.SEED_HANDLE ?? 'admin';
const PASSWORD = process.env.SEED_PASSWORD; // supply via env, do not hardcode
const AUTH_ROOT = process.env.AUTH_DATA_DIR ?? 'var/auth';
const PACKET_PATH = process.env.SEED_PACKET_PATH ??
  join(AUTH_ROOT, 'operator', 'auth-seed.packet');

interface SeedPacket {
  version: 1;
  claim: InertFirstUserClaim;
  finalization: FirstUserBootstrapFinalization;
  operator: {
    totpSecret: string;
    qrCodeUrl: string;
    backupCodes: string[];
  };
}

function packetKey(secret: string): Buffer {
  return createHash('sha256').update(secret, 'utf8').digest();
}

async function persistPacket(path: string, packet: SeedPacket, secret: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', packetKey(secret), iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(packet), 'utf8'),
    cipher.final(),
  ]);
  const envelope = JSON.stringify({
    version: 1,
    iv: iv.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
  });

  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${randomUUID()}.tmp`;
  const file = await open(temporary, 'wx', 0o600);
  try {
    await file.writeFile(envelope, 'utf8');
    await file.sync();
  } finally {
    await file.close();
  }
  try {
    // link() publishes the complete packet without replacing a contender's
    // packet if two seed processes start together.
    await link(temporary, path);
    const directory = await open(dirname(path), 'r');
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  } finally {
    await unlink(temporary).catch(() => undefined);
  }
}

async function recoverPacket(path: string, secret: string): Promise<SeedPacket | null> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
  const envelope = JSON.parse(raw) as {
    version: 1;
    iv: string;
    tag: string;
    ciphertext: string;
  };
  if (envelope.version !== 1) throw new Error('Unsupported seed packet');
  const decipher = createDecipheriv(
    'aes-256-gcm',
    packetKey(secret),
    Buffer.from(envelope.iv, 'base64url'),
  );
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64url'));
  const cleartext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64url')),
    decipher.final(),
  ]);
  return JSON.parse(cleartext.toString('utf8')) as SeedPacket;
}

async function createPacket(
  tenantId: string,
  totp: TOTPService,
): Promise<SeedPacket> {
  if (!PASSWORD) throw new Error('SEED_PASSWORD required');
  const claimedAt = new Date().toISOString();
  const claim: InertFirstUserClaim = {
    version: 1,
    tenantId,
    attemptId: randomUUID(),
    actor: {
      id: randomUUID(),
      handle: HANDLE,
      isActive: false,
      totpEnabled: false,
      sessionAuthority: false,
      backupCodesGenerated: false,
    },
    claimedAt,
  };
  const passwordHash = await hashPassword(PASSWORD, { rounds: 12 });
  const generated = await totp.generateSecret(claim.actor.handle);
  const encrypted = totp.encrypt(generated.secret);
  const backupCodes = generateBackupCodes(10);
  const finalizedAt = new Date().toISOString();
  const finalization: FirstUserBootstrapFinalization = {
    version: 1,
    tenantId,
    attemptId: claim.attemptId,
    finalizedAt,
    user: {
      id: claim.actor.id,
      handle: claim.actor.handle,
      displayName: HANDLE,
      passwordHash,
      role: AdminRole.SUPER_ADMIN,
      isActive: true,
      totpEnabled: true,
      totpSecretId: claim.actor.handle,
      needsOnboarding: false,
      onboardingStep: 0,
      createdAt: claimedAt,
      updatedAt: finalizedAt,
    },
    totpSecret: {
      userId: claim.actor.id,
      handle: claim.actor.handle,
      encryptedSecret: encrypted.encrypted,
      iv: encrypted.iv,
      authTag: encrypted.tag,
      salt: encrypted.salt,
      createdAt: finalizedAt,
      backupCodesGenerated: true,
      version: 1,
    },
    backupCodes: {
      ...createBackupCodeSet(claim.actor.id, backupCodes),
      generatedAt: finalizedAt,
    },
  };
  return {
    version: 1,
    claim,
    finalization,
    operator: {
      totpSecret: generated.secret,
      qrCodeUrl: generated.qrCodeUrl ?? '',
      backupCodes,
    },
  };
}

async function main() {
  const encryptionKey = process.env.TOTP_ENCRYPTION_KEY;
  if (!encryptionKey) throw new Error('TOTP_ENCRYPTION_KEY required');
  const recoveryKey = process.env.SEED_RECOVERY_KEY;
  if (!recoveryKey || recoveryKey.length < 32) {
    throw new Error('SEED_RECOVERY_KEY must be a stable 32+ character secret');
  }
  const tenantId = resolveAuthTenantId({
    AUTH_TENANT_ID: process.env.AUTH_TENANT_ID,
  });

  const storage = createFileStorageAdapter({
    authDir: join(AUTH_ROOT, 'records'),
    totpDir: join(AUTH_ROOT, 'secrets'),
  });
  await storage.init();

  const totp = new TOTPService({ encryptionKey, issuer: 'My App' });
  // Receipt-first recovery: a lost successful response never re-discloses
  // operator material or generates replacement credentials.
  const existingReceipt = await storage.getFirstUserBootstrapReceipt(tenantId);
  if (existingReceipt) {
    const recoveryPacket = await recoverPacket(PACKET_PATH, recoveryKey);
    if (recoveryPacket) {
      if (recoveryPacket.claim.tenantId !== tenantId) {
        throw new Error('Seed packet belongs to a different tenant');
      }
      // Exact replay proves the residual packet matches the immutable receipt.
      await storage.finalizeFirstUserBootstrap(recoveryPacket.finalization);
      await unlink(PACKET_PATH);
    }
    console.log('super_admin already created:', existingReceipt.handle);
    return;
  }

  let packet = await recoverPacket(PACKET_PATH, recoveryKey);
  if (!packet) {
    packet = await createPacket(tenantId, totp);
    // Durable encrypted custody happens before the inert claim or any commit.
    await persistPacket(PACKET_PATH, packet, recoveryKey);
  }
  if (packet.claim.tenantId !== tenantId) {
    throw new Error('Seed packet belongs to a different tenant');
  }

  await storage.claimFirstUserBootstrap(packet.claim);

  // Put the factor in the operator's authenticator and save the recovery
  // codes before any credential or role becomes authoritative.
  console.log('Scan this TOTP secret in your authenticator app:');
  console.log('  otpauth secret:', packet.operator.totpSecret);
  console.log('  qr (data url):', packet.operator.qrCodeUrl);
  console.log('Backup codes (store now, shown once):');
  for (const code of packet.operator.backupCodes) console.log('  ', code);

  const prompt = createInterface({ input: stdin, output: stdout });
  try {
    const code = await prompt.question('Enter the current 6-digit TOTP code: ');
    if (!(await totp.verifyToken({
      handle: packet.claim.actor.handle,
      secret: packet.operator.totpSecret,
      qrCodeUrl: packet.operator.qrCodeUrl,
      createdAt: new Date(packet.claim.claimedAt),
    }, code))) {
      throw new Error('TOTP verification failed; no authority was finalized');
    }
    const confirmation = await prompt.question(
      'Type COMMIT after storing the backup codes: ',
    );
    if (confirmation !== 'COMMIT') {
      throw new Error('Bootstrap cancelled; no authority was finalized');
    }
  } finally {
    prompt.close();
  }

  const receipt = await storage.finalizeFirstUserBootstrap(packet.finalization);
  await unlink(PACKET_PATH);
  console.log('super_admin created:', receipt.handle);
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

The encrypted packet is published durably before the inert claim. A restart
recovers the identical claim, canonical finalization, TOTP input, and plaintext
operator backup codes rather than regenerating any digest-bearing field. The
script renders operator material before commit, uses receipt-first recovery
after a lost response, and deletes the packet only after an exact successful
finalization replay. Keep `SEED_RECOVERY_KEY` in a secret store and keep
`SEED_PACKET_PATH` on private durable storage; neither belongs in git. If the
ten-minute claim window expires before commit, stop and use an explicit
operator recovery procedure to retire the stale inert packet and create a new
one. Do not silently regenerate material under the same attempt.

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
// keep secret.secret in a short-lived server-side store until verified;
// do not put it in a signed or encrypted browser cookie

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

> **Unreleased 0.8 source only.** The current PostgreSQL/Redis adapters cannot
> back this flow because they do not implement the native atomic storage
> protocol. A multi-replica deployment also needs a durable attempt store that
> passes `runBootstrapAttemptStoreConformance`.

If you prefer a guided `/bootstrap` route over a seed script, the package ships
`BootstrapService` (`createBootstrapService`). It enforces the "no users yet"
precondition, validates the handle, and its `complete()` step hardcodes
`role: 'super_admin'`, so it is purpose-built for the first admin. Its config
takes callbacks for the TOTP primitives:

The unreleased 0.8 service uses the same atomic claim/finalize protocol. Its
browser state is only an opaque attempt reference. All credential material and
the compare-and-set prepared finalization stay in an explicit server-side
`BootstrapAttemptStore`.

```ts
import {
  MemoryBootstrapAttemptStore,
  createBootstrapService,
} from '@tummycrypt/tinyland-auth';
import {
  generateTOTPSecret,
  generateTOTPUri,
  generateTOTPQRCode,
} from '@tummycrypt/tinyland-auth/totp';
import { totp } from '$lib/server/auth.js';
import { storage } from '$lib/server/storage.js';

const bootstrap = createBootstrapService({
  storage,                       // atomic bootstrap + status/audit reads
  tenantId: process.env.AUTH_TENANT_ID!,
  // Single-process only. Multi-replica apps must inject durable CAS custody.
  attemptStore: new MemoryBootstrapAttemptStore(),
  appName: 'My App',
  bcryptRounds: 12,
  backupCodesCount: 10,
  generateTOTPSecret,            // () => string (base32 secret)
  generateQRCode: (handle, secret, issuer) =>
    generateTOTPQRCode(generateTOTPUri(secret, issuer, handle)), // () => Promise<data-url>
  encryptTOTPSecret: async (handle, secret) => {
    const enc = totp.encrypt(secret);
    return {
      userId: 'pending',         // service binds the stored factor to the claimed actor
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
  decryptTOTPSecret: async (stored) => totp.decrypt({
    encrypted: stored.encryptedSecret,
    salt: stored.salt,
    iv: stored.iv,
    tag: stored.authTag,
  }),
  // verifyTOTP: (secret: string, token: string) => boolean | Promise<boolean>
  // ILLUSTRATIVE seam: complete() awaits this callback and finalizes only when
  // it resolves to the exact value true. Configure the verifier to match the
  // package (step 30, window 1, SHA1, 6 digits). A rejection or false result
  // fails closed. If you cannot add that verifier, prefer the seed script in
  // section 6, which needs no in-app code round-trip.
  verifyTOTP: async (secret, token) => {
    // e.g. otplib authenticator.check(token, secret) with matching options
    throw new Error('supply a TOTP verifier');
  },
});
```

Flow: `getStatus()` reports both first-user eligibility and whether finalized
authority metadata is present with decryptable TOTP ciphertext. It is not a
live authenticator-code canary. `initiate({ handle, password, displayName,
email? })` returns
`{ state, qrCodeUrl, backupCodes }`; `state` is `{ version: 1, attemptId }` and
can be carried to `complete(state, { handle, totpCode })`. Profile updates use
`await bootstrap.updateProfile(state, profile)` so profile data also stays in
server custody. Completion verifies the code, freezes one deterministic
finalization, commits the user/TOTP/backup-code authority atomically, and
returns the safe user. Exact lost-response retries resolve from the immutable
receipt before expiry or TOTP checks. Plaintext pending credentials are erased
on the normal success path before the response returns. Receipt replay never
re-emits backup codes, even if cleanup failed and left the pending record
behind; save the one-time codes returned by `initiate`. Durable attempt stores
must enforce expiry as a backstop for process crashes and cleanup failures.

`complete()` never returns backup codes, including its first success. The
one-time disclosure is the `initiate()` response. The attempt and storage claim
share one fixed ten-minute (600,000 ms) lifetime. The exact boundary remains
valid; 600,001 ms is expired, with no clock-skew grace added to expiry
acceptance. Shorter or longer service lifetimes are rejected so the
browser-state and storage-authority windows cannot diverge.

The package does not authorize initiation. Before calling `initiate()`, the
downstream app must require an attended operator-only/local gate, such as a
loopback CLI, a private administrative control plane, or an equivalent
deployment bootstrap gate. Never publish initiation as an unauthenticated or
merely rate-limited route. Opaque browser state limits credential exposure but
does not decide who may claim first-user authority.

Protect the attempt id as a bearer capability in an httpOnly cookie or an
equivalent server-bound transport. Never serialize the pending attempt object:
it contains the password hash, raw TOTP secret, and plaintext backup codes. The
attempt store must implement atomic create and prepare-finalization operations;
an ordinary cache get/set pair is not sufficient for multiple replicas.
The default attempt-id generator is cryptographically random. A custom
`generateAttemptId` must preserve at least 128 bits of entropy.

The seed script in section 6 is the lower-friction path for most apps; reach for
`BootstrapService` when you want the whole thing to happen inside the running app
with no shell access.

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

## Provenance (0.7.1 release plus unreleased 0.8 bootstrap source)

The general auth APIs below are public exports of
`@tummycrypt/tinyland-auth@0.7.1`. The atomic first-user storage protocol,
`MemoryBootstrapAttemptStore`, and opaque `BootstrapService` state are
unreleased 0.8 source and must not be claimed as available from 0.7.1.

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
- `FileStorageConfig` (`authDir`, `totpDir`, `sessionMaxAge`, bounded bootstrap
  lock timeout/retry controls):
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
persisting `lastUsedTotpStep`, and a string-based TOTP verifier for
`BootstrapService`) that are app policy or supplied glue rather than package
exports. Only the APIs explicitly identified above as released are verified
`0.7.1` API; the atomic bootstrap storage/service material is unreleased 0.8
source.
