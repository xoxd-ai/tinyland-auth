#!/usr/bin/env node
// RS6 / RP2 runtime proof on the built package (TIN-5766): the durable
// first-admin and enrollment coordinators in `./storage` verify TOTP codes
// themselves. No caller-supplied verifier, secret generator or cipher is ever
// called, and the deny-only `beforeComplete` gate cannot accept a code.
//
// Usage: node scripts/check-totp-authority.mjs <package-dir>
//
// <package-dir> is the package as it is delivered: Bazel `//:pkg`
// (//:totp_authority_artifact_test) or an emulation of it
// (tests/production-artifact.test.ts). The probe runs in a fresh plain-Node
// process for NODE_ENV production, unset and development, so no test
// transform, seam or environment can help it. The 1.1.0 candidate failed this
// check: `verifyTokenWithStep: async () => ({ valid: true })` minted
// `{ handle: 'attacker', role: 'super_admin' }` with the code 000000.

import { spawnSync } from 'node:child_process';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const PROBE_FLAG = '--probe';

async function probe(pkgDir) {
  const entry = (file) => pathToFileURL(join(pkgDir, 'dist', file)).href;
  const storageEntry = await import(entry('storage/index.js'));
  const totpEntry = await import(entry('totp/index.js'));
  const { generateAuthenticatorToken } = await import(entry('totp/otplib-compat.js'));
  const { FileBootstrapCoordinator, FileTotpEnrollmentCoordinator } = storageEntry;
  const { TOTPService, createTOTPService } = totpEntry;
  const root = mkdtempSync(join(tmpdir(), 'tinyland-auth-totp-authority-'));
  const out = {};
  try {
    const key = 'totp-authority-probe-key-0123456789abcdef';
    const fresh = () => createTOTPService({ encryptionKey: key, issuer: 'RS6 probe' });
    const alwaysValid = async () => ({ valid: true, step: 1 });
    const PINNED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
    const users = [];
    let factor = null;
    let codes = null;
    let directoryIndex = 0;
    const bootstrapConfig = (totp, extra = {}) => ({
      directory: join(root, `bootstrap-${directoryIndex++}`),
      scope: 'rs6-probe',
      totp,
      storage: {
        getAllUsers: async () => users.map((user) => ({ ...user })),
        getTOTPSecret: async () => factor,
        getBackupCodes: async () => codes,
      },
      withExclusiveAuth: (operation) => operation(),
      project: async (completion) => {
        factor ??= completion.totpSecret;
        codes ??= completion.backupCodes;
        if (!users.length) users.push(completion.user);
      },
      ...extra,
    });
    const refused = (construct) => {
      try {
        construct();
        return false;
      } catch (error) {
        return error?.code === 'INVALID';
      }
    };

    // 1. Shapes that are not a genuine TOTPService are refused at construction.
    const real = fresh();
    const lookAlike = {
      generateSecret: real.generateSecret.bind(real),
      generateQRCode: real.generateQRCode.bind(real),
      encrypt: real.encrypt.bind(real),
      decrypt: real.decrypt.bind(real),
      verifyTokenWithStep: alwaysValid,
    };
    const delegatingWrapper = { ...lookAlike, verifyTokenWithStep: (...args) => real.verifyTokenWithStep(...args) };
    class AlwaysValid extends TOTPService {
      async verifyTokenWithStep() { return { valid: true, step: 1 }; }
    }
    const ownOverride = fresh();
    ownOverride.verifyTokenWithStep = alwaysValid;
    const pinnedSeed = fresh();
    pinnedSeed.generateSecret = async (handle) => ({ handle, secret: PINNED, createdAt: new Date() });
    const reprototyped = Object.setPrototypeOf(fresh(), lookAlike);
    const shapes = {
      lookAlike,
      delegatingWrapper,
      subclass: new AlwaysValid({ encryptionKey: key, issuer: 'RS6 probe' }),
      ownOverride,
      pinnedSeed,
      reprototyped,
      inherited: Object.create(real),
    };
    out.refusedBootstrap = {};
    out.refusedEnrollment = {};
    for (const [name, totp] of Object.entries(shapes)) {
      out.refusedBootstrap[name] = refused(() => new FileBootstrapCoordinator(bootstrapConfig(totp)));
      out.refusedEnrollment[name] = refused(() => new FileTotpEnrollmentCoordinator({
        directory: join(root, `enrollment-${name}`),
        totp,
        loadCurrent: async () => { throw new Error('unused'); },
        project: async () => { throw new Error('unused'); },
      }));
    }
    out.refusedDenyHookShape = refused(() => new FileBootstrapCoordinator(bootstrapConfig(fresh(), { beforeComplete: 'allow' })));

    // 2. A genuine coordinator ignores verifier patches made after construction.
    const service = fresh();
    let gate = async () => undefined;
    const config = bootstrapConfig(service, { beforeComplete: (operation) => gate(operation) });
    const coordinator = new FileBootstrapCoordinator(config);
    const setup = await coordinator.begin({ handle: 'attacker', passwordHash: '$2b$04$' + 'A'.repeat(53) });
    out.secretNotPinned = setup.secret !== PINNED && /^[A-Z2-7]{32,}$/.test(setup.secret);
    await coordinator.acknowledgeBackupCodes(setup.reference);
    const codeAt = (offsetSeconds) => generateAuthenticatorToken(setup.secret, Math.floor(Date.now() / 1000) + offsetSeconds);
    const genuineCode = () => codeAt(0);
    const wrongCode = () => {
      // Matches none of the steps the verifier accepts around now.
      const window = new Set([-60, -30, 0, 30, 60].map(codeAt));
      for (let n = 0; ; n++) {
        const candidate = String(n).padStart(6, '0');
        if (!window.has(candidate)) return candidate;
      }
    };
    const originalPrototypeVerify = TOTPService.prototype.verifyTokenWithStep;
    service.verifyTokenWithStep = alwaysValid;
    TOTPService.prototype.verifyTokenWithStep = alwaysValid;
    config.totp = { verifyTokenWithStep: alwaysValid };
    coordinator.totp = { verifyTokenWithStep: alwaysValid, decrypt: (value) => service.decrypt(value), encrypt: (value) => service.encrypt(value) };
    const attempt = async (token) => {
      try {
        await coordinator.complete({ reference: setup.reference, token });
        return 'completed';
      } catch (error) {
        return error?.code ?? error?.message ?? 'error';
      }
    };
    out.patchedWrong = await attempt(wrongCode());
    out.patchedZeros = await attempt(new Set([-60, -30, 0, 30, 60].map(codeAt)).has('000000') ? wrongCode() : '000000');
    out.usersAfterPatched = users.length;

    // 3. beforeComplete is deny-only.
    gate = async () => ({ valid: true, step: 1 });
    out.affirmingHookWrong = await attempt(wrongCode());
    gate = async () => { throw Object.assign(new Error('writes closed'), { code: 'WRITES_CLOSED' }); };
    out.denyingHookGenuine = await attempt(genuineCode());
    out.usersAfterHooks = users.length;

    // 4. Non-vacuous: the genuine code still completes through the same coordinator.
    gate = async () => undefined;
    out.genuine = await attempt(genuineCode());
    out.minted = users.map((user) => ({ handle: user.handle, role: user.role }));
    TOTPService.prototype.verifyTokenWithStep = originalPrototypeVerify;
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  return out;
}

const EXPECTED_SHAPES = {
  lookAlike: true,
  delegatingWrapper: true,
  subclass: true,
  ownOverride: true,
  pinnedSeed: true,
  reprototyped: true,
  inherited: true,
};
const EXPECTED = {
  refusedBootstrap: EXPECTED_SHAPES,
  refusedEnrollment: EXPECTED_SHAPES,
  refusedDenyHookShape: true,
  secretNotPinned: true,
  patchedWrong: 'INVALID',
  patchedZeros: 'INVALID',
  usersAfterPatched: 0,
  affirmingHookWrong: 'INVALID',
  denyingHookGenuine: 'WRITES_CLOSED',
  usersAfterHooks: 0,
  genuine: 'completed',
  minted: [{ handle: 'attacker', role: 'super_admin' }],
};

if (process.argv[2] === PROBE_FLAG) {
  const result = await probe(process.argv[3]);
  process.stdout.write(JSON.stringify(result));
} else {
  const pkgArg = process.argv[2];
  if (!pkgArg) {
    console.error('usage: check-totp-authority.mjs <package-dir>');
    process.exit(2);
  }
  const pkgDir = realpathSync(resolve(pkgArg));
  const self = fileURLToPath(import.meta.url);
  const failures = [];
  for (const [label, nodeEnv] of [['production', 'production'], ['unset', undefined], ['development', 'development']]) {
    const env = { ...process.env };
    delete env.NODE_ENV;
    if (nodeEnv !== undefined) env.NODE_ENV = nodeEnv;
    const run = spawnSync(process.execPath, [self, PROBE_FLAG, pkgDir], { env, encoding: 'utf8' });
    if (run.status !== 0) {
      failures.push(`NODE_ENV ${label}: probe exited ${run.status}: ${run.stderr.trim().split('\n').slice(0, 6).join(' | ')}`);
      continue;
    }
    const actual = JSON.parse(run.stdout);
    for (const [key, expected] of Object.entries(EXPECTED)) {
      if (JSON.stringify(actual[key]) !== JSON.stringify(expected)) {
        failures.push(`NODE_ENV ${label}: ${key} is ${JSON.stringify(actual[key])}, expected ${JSON.stringify(expected)}`);
      }
    }
  }
  if (failures.length > 0) {
    for (const failure of failures) console.error(`totp authority error: ${failure}`);
    process.exit(1);
  }
  console.log(
    'totp authority clean: ./storage coordinators refuse 7 non-genuine TOTP shapes, ignore patched verifiers, ' +
      'keep beforeComplete deny-only, and mint super_admin only for the genuine code (NODE_ENV production, unset, development)',
  );
}
