import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import {
  appendFileSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

// RS5 / RS6 (TIN-5766, RP2): prove on built output that
//   - a production package and a production bundle of every public entry carry
//     no testing symbol, no testing sentinel and no removed bypass name, and
//     that the check is not vacuous (deliberate contamination turns it red);
//   - the testing entry refuses to load unless NODE_ENV is exactly "test".
// Bazel runs the same check against the real //:pkg artifact
// (//:production_artifact_test) and CI runs it against the `pnpm pack`
// tarball (`pnpm check:production-artifact`).

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const CHECK_SCRIPT = join(ROOT, 'scripts/check-production-artifact.mjs');
const SENTINEL = 'tinyland-auth-testing-entry-5a9aa858497cf8b557fcbb77';
const require = createRequire(import.meta.url);
const TSC = require.resolve('typescript/bin/tsc');

let work = '';
let cleanPkg = '';
let testingBuild = '';

function tsc(project: string, outDir: string): void {
  const result = spawnSync(process.execPath, [TSC, '-p', project, '--outDir', outDir], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error(`tsc -p ${project} failed:\n${result.stdout}\n${result.stderr}`);
  }
}

/** Emulates `pnpm pack`: package.json plus the manifest's "files". */
function assemblePackage(dir: string, distDir: string): void {
  mkdirSync(dir, { recursive: true });
  const manifest = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
    files: string[];
  };
  expect(manifest.files).toEqual(['dist', 'README.md']);
  writeFileSync(join(dir, 'package.json'), readFileSync(join(ROOT, 'package.json')));
  cpSync(join(ROOT, 'README.md'), join(dir, 'README.md'));
  cpSync(distDir, join(dir, 'dist'), { recursive: true });
}

function checkArtifact(dir: string): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, [CHECK_SCRIPT, dir], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, NODE_ENV: 'production' },
  });
}

function contaminatedCopy(name: string): string {
  const dir = join(work, name);
  cpSync(cleanPkg, dir, { recursive: true });
  return dir;
}

/** Evaluate `body` in a fresh Node process after importing the testing build. */
function importTestingEntry(env: Record<string, string | undefined>, body = '') {
  const entry = join(testingBuild, 'testing/index.js');
  const childEnv: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (key !== 'NODE_ENV' && key !== 'TINYLAND_AUTH_TEST_ADMISSION' && value !== undefined) {
      childEnv[key] = value;
    }
  }
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined) childEnv[key] = value;
  }
  const script = `const t = await import(${JSON.stringify(entry)});\n${body}`;
  return spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: work,
    encoding: 'utf8',
    env: childEnv,
  });
}

beforeAll(() => {
  work = realpathSync(mkdtempSync(join(tmpdir(), 'tinyland-auth-artifact-test-')));
  // Let built files under `work` resolve runtime deps (otplib, bcryptjs, ...).
  symlinkSync(join(ROOT, 'node_modules'), join(work, 'node_modules'), 'dir');

  const prodDist = join(work, 'build-production');
  tsc('tsconfig.json', prodDist);
  cleanPkg = join(work, 'pkg-clean');
  assemblePackage(cleanPkg, prodDist);

  testingBuild = join(work, 'build-testing');
  tsc('tsconfig.testing.json', testingBuild);
}, 240_000);

afterAll(() => {
  if (work) rmSync(work, { recursive: true, force: true });
});

describe('production build excludes the testing entry (RS5)', () => {
  it('emits no testing module into the production dist', () => {
    const files = spawnSync('find', ['.', '-path', '*testing*'], {
      cwd: join(cleanPkg, 'dist'),
      encoding: 'utf8',
    });
    expect(files.stdout.trim()).toBe('');
  });

  it('passes the artifact check: no testing symbol or sentinel in the package or a production bundle', () => {
    const result = checkArtifact(cleanPkg);
    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/production artifact clean: @tummycrypt\/tinyland-auth@\d+\.\d+\.\d+/);
    expect(result.stdout).toContain('./testing unresolvable');
  }, 120_000);

  it('turns red when a testing symbol and the sentinel are re-exported from the main entry', () => {
    const dir = contaminatedCopy('pkg-leak-main-entry');
    writeFileSync(
      join(dir, 'dist/leak.js'),
      `export const leakMarker = ${JSON.stringify(SENTINEL)};\n` +
        'export function createTestAdmissionIssuer() { return leakMarker; }\n',
    );
    appendFileSync(join(dir, 'dist/index.js'), "\nexport * from './leak.js';\n");

    const result = checkArtifact(dir);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`production bundle contains ${JSON.stringify(SENTINEL)}`);
    expect(result.stderr).toContain('production bundle contains "createTestAdmissionIssuer"');
    expect(result.stderr).toContain('shipped file dist/leak.js contains');
  }, 120_000);

  it('turns red when the internal seam writer becomes reachable from a public entry', () => {
    const dir = contaminatedCopy('pkg-leak-seam-writer');
    appendFileSync(join(dir, 'dist/index.js'), "\nexport { installSeams } from './core/seams/index.js';\n");

    const result = checkArtifact(dir);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('production bundle contains "installSeams"');
  }, 120_000);

  it('turns red when the testing build ships inside the package', () => {
    const dir = contaminatedCopy('pkg-ships-testing');
    cpSync(join(testingBuild, 'testing'), join(dir, 'dist/testing'), { recursive: true });

    const result = checkArtifact(dir);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('package ships a testing path: dist/testing/index.js');
    expect(result.stderr).toContain(JSON.stringify(SENTINEL));
  }, 120_000);

  it('turns red when the manifest exports ./testing, even under a test-only condition', () => {
    const dir = contaminatedCopy('pkg-exports-testing');
    const manifestPath = join(dir, 'package.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    manifest.exports['./testing'] = {
      test: { import: './dist-testing/testing/index.js' },
    };
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    const result = checkArtifact(dir);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('package.json exports a testing entry: ./testing');
  }, 120_000);

  it('turns red when a removed RS6 bypass name comes back', () => {
    const dir = contaminatedCopy('pkg-rs6-regression');
    appendFileSync(
      join(dir, 'dist/core/totp/index.js'),
      '\nexport const bypass = { devMode: true, testCode: "000000" };\n',
    );

    const result = checkArtifact(dir);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('contains "devMode"');
    expect(result.stderr).toContain('contains "testCode"');
  }, 120_000);
});

/** Run an ES module script in a fresh Node process with exactly `env` for NODE_ENV. */
function runNode(script: string, nodeEnv: string | undefined) {
  const childEnv: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (key !== 'NODE_ENV' && value !== undefined) childEnv[key] = value;
  }
  if (nodeEnv !== undefined) childEnv.NODE_ENV = nodeEnv;
  return spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: work,
    encoding: 'utf8',
    env: childEnv,
  });
}

describe('production entry has no development or seam bypass (RP2)', () => {
  const distUrl = (file: string) => JSON.stringify(new URL(`file://${join(cleanPkg, 'dist', file)}`).href);

  // Every host and NODE_ENV combination the 0.7.x auto-detection admitted
  // without a client certificate, plus a stale caller flag.
  const mtlsProbe = () => `
    const adapter = await import(${distUrl('adapters/sveltekit/mtls.js')});
    const core = await import(${distUrl('core/security/mtls.js')});
    const event = (host, headers = {}) => ({
      url: new URL('https://' + host + '/admin'),
      request: new Request('https://' + host + '/admin', { headers }),
      locals: {},
    });
    const out = {};
    for (const host of ['auth.example.com', 'localhost', '127.0.0.1', 'evil.local']) {
      out[host] = adapter.requireMTLS(event(host));
    }
    out.staleFlagCore = core.extractCertificate({}, { isDevelopment: true }).isValid;
    out.staleFlagAdapter = adapter.extractCertificateFromEvent(event('localhost'), { isDevelopment: true }).isValid;
    const withCert = event('auth.example.com', {
      'X-SSL-Client-Cert': '-----BEGIN CERTIFICATE-----MIIBfake-----END CERTIFICATE-----',
      'X-SSL-Client-Verify': 'SUCCESS',
    });
    out.withCert = adapter.requireMTLS(withCert);
    out.fingerprint = withCert.locals.mTLSCert.fingerprint.startsWith('sha256:');
    out.failedVerify = adapter.requireMTLS(event('localhost', {
      'X-SSL-Client-Cert': 'x', 'X-SSL-Client-Verify': 'FAILED:unknown ca',
    }));
    process.stdout.write(JSON.stringify(out));
  `;

  for (const [label, nodeEnv] of [
    ['production', 'production'],
    ['unset', undefined],
    ['development', 'development'],
  ] as Array<[string, string | undefined]>) {
    it(`requireMTLS has no host or NODE_ENV pass for a request without certificate headers (NODE_ENV ${label})`, () => {
      const result = runNode(mtlsProbe(), nodeEnv);
      expect(result.stderr).toBe('');
      expect(result.status).toBe(0);
      expect(JSON.parse(result.stdout)).toEqual({
        'auth.example.com': false,
        localhost: false,
        '127.0.0.1': false,
        'evil.local': false,
        staleFlagCore: false,
        staleFlagAdapter: false,
        withCert: true,
        fingerprint: true,
        failedVerify: false,
      });
    });
  }

  it('the shipped seam writer refuses outside NODE_ENV=test, even through a file-URL import', () => {
    const script = `
      const seams = await import(${distUrl('core/seams/index.js')});
      try { seams.installSeams({}, { clock: { now: () => 0 } }); process.stdout.write('installed'); }
      catch (error) { process.stdout.write('refused: ' + error.message); }
    `;
    for (const nodeEnv of ['production', undefined, '', 'development', 'TEST']) {
      const result = runNode(script, nodeEnv);
      expect(result.status).toBe(0);
      expect(result.stdout).toMatch(/^refused: Test seams can only be installed when NODE_ENV is exactly "test"/);
    }
    expect(runNode(script, 'test').stdout).toBe('installed');
  });

  it('generateSecurePassword works in plain Node ESM (no CommonJS require)', () => {
    const script = `
      const { generateSecurePassword } = await import(${distUrl('index.js')});
      process.stdout.write(generateSecurePassword(24));
    `;
    const result = runNode(script, 'production');
    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
    expect(result.stdout).toHaveLength(24);
  });

  it('session cookies stay Secure unless NODE_ENV is explicitly development or test', () => {
    const script = `
      const { DEFAULT_COOKIE_CONFIG } = await import(${distUrl('adapters/sveltekit/session-cookies.js')});
      process.stdout.write(String(DEFAULT_COOKIE_CONFIG.secure));
    `;
    expect(runNode(script, 'production').stdout).toBe('true');
    expect(runNode(script, undefined).stdout).toBe('true');
    expect(runNode(script, '').stdout).toBe('true');
    expect(runNode(script, 'development').stdout).toBe('false');
    expect(runNode(script, 'test').stdout).toBe('false');
  });

  // R1-B1: 0.7.x BootstrapServiceConfig took a caller-supplied verifyTOTP, so
  // `verifyTOTP: () => true` minted the first super_admin with any code.
  const bootstrapProbe = () => `
    const pkg = await import(${distUrl('index.js')});
    const otp = await import(${distUrl('totp/otplib-compat.js')});
    const storage = new pkg.MemoryStorageAdapter();
    await storage.init();
    const service = pkg.createBootstrapService({
      storage,
      appName: 'RP2',
      bcryptRounds: 4,
      backupCodesCount: 3,
      generateQRCode: async () => 'qr',
      encryptTOTPSecret: async (handle, secret) => ({ handle, encryptedSecret: 'x' + secret.length }),
      // Stale 0.7.x keys: both must be ignored.
      verifyTOTP: () => true,
      generateTOTPSecret: () => 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
    });
    const request = { handle: 'firstadmin', password: 'pw-A1!aaaaaaa', displayName: 'A' };
    const { state } = await service.initiate(request);
    const real = otp.generateAuthenticatorToken(state.totpSecret);
    const out = {
      pinnedSecretIgnored: state.totpSecret !== 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
      secretLength: state.totpSecret.length >= 32,
    };
    const wrong = real === '000000' ? '000001' : '000000';
    out.arbitrary = [];
    for (const code of [wrong, '', 'accept', real + '0', undefined]) {
      const result = await service.complete(state, { handle: 'firstadmin', totpCode: code });
      out.arbitrary.push(result.success);
    }
    out.usersAfterArbitrary = await storage.hasUsers();
    const ok = await service.complete(state, { handle: 'firstadmin', totpCode: real });
    out.realCode = ok.success && ok.user.role;
    const replay = await service.complete(state, { handle: 'firstadmin', totpCode: real });
    out.replay = replay.success;
    process.stdout.write(JSON.stringify(out));
  `;

  for (const [label, nodeEnv] of [
    ['production', 'production'],
    ['unset', undefined],
    ['development', 'development'],
  ] as Array<[string, string | undefined]>) {
    it(`first-admin bootstrap verifies the code itself; no caller verifier is honoured (NODE_ENV ${label})`, () => {
      const result = runNode(bootstrapProbe(), nodeEnv);
      expect(result.stderr).toBe('');
      expect(result.status).toBe(0);
      expect(JSON.parse(result.stdout)).toEqual({
        pinnedSecretIgnored: true,
        secretLength: true,
        arbitrary: [false, false, false, false, false],
        usersAfterArbitrary: false,
        realCode: 'super_admin',
        replay: false,
      });
    });
  }

  it('the artifact check turns red when a caller-injected bootstrap verifier comes back', () => {
    const dir = contaminatedCopy('pkg-bootstrap-verifier-regression');
    appendFileSync(
      join(dir, 'dist/modules/bootstrap/index.js'),
      '\nexport const legacy = (config) => config.verifyTOTP;\n',
    );

    const result = checkArtifact(dir);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('contains "verifyTOTP"');
  }, 120_000);

  it('the artifact check turns red when the mTLS development auto-pass comes back', () => {
    const dir = contaminatedCopy('pkg-mtls-dev-regression');
    appendFileSync(
      join(dir, 'dist/core/security/mtls.js'),
      "\nexport function detectDevelopment() { return { isDevelopment: true, fingerprint: 'dev-mode-no-cert' }; }\n",
    );

    const result = checkArtifact(dir);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('contains "isDevelopment"');
    expect(result.stderr).toContain('contains "detectDevelopment"');
    expect(result.stderr).toContain('contains "dev-mode-no-cert"');
  }, 120_000);
});

describe('testing entry load gate (RS5)', () => {
  const refusals: Array<[string, string | undefined]> = [
    ['unset', undefined],
    ['empty', ''],
    ['production', 'production'],
    ['development', 'development'],
    ['uppercase TEST', 'TEST'],
    ['padded test', ' test'],
  ];

  for (const [label, nodeEnv] of refusals) {
    it(`refuses to load when NODE_ENV is ${label}`, () => {
      const result = importTestingEntry({ NODE_ENV: nodeEnv, TINYLAND_AUTH_TEST_ADMISSION: 'enabled' });
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain('TestingEntryRefusedError');
      expect(result.stderr).toContain('refused to load');
      expect(result.stderr).toContain(SENTINEL);
      expect(result.stderr).toContain(nodeEnv === undefined ? 'NODE_ENV is unset' : `NODE_ENV is ${JSON.stringify(nodeEnv)}`);
    });
  }

  it('loads only under NODE_ENV=test, and admission still needs the explicit opt-in', () => {
    const body = [
      "process.stdout.write(JSON.stringify({",
      "  sentinel: t.TESTING_ENTRY_SENTINEL,",
      "  hasIssuer: typeof t.createTestAdmissionIssuer === 'function',",
      "  allowed: t.isTestAdmissionAllowed(),",
      "}));",
    ].join('\n');

    const closed = importTestingEntry({ NODE_ENV: 'test' }, body);
    expect(closed.stderr).toBe('');
    expect(closed.status).toBe(0);
    expect(JSON.parse(closed.stdout)).toEqual({ sentinel: SENTINEL, hasIssuer: true, allowed: false });

    const open = importTestingEntry({ NODE_ENV: 'test', TINYLAND_AUTH_TEST_ADMISSION: 'enabled' }, body);
    expect(open.status).toBe(0);
    expect(JSON.parse(open.stdout).allowed).toBe(true);
  });

  it('re-checks the live environment on use, so flipping NODE_ENV after load closes it', () => {
    const body = [
      "process.env.NODE_ENV = 'production';",
      'const errors = [];',
      "for (const call of [() => t.assertTestEnvironment(), () => t.assertTestAdmissionAllowed(), () => t.createManualClock(0) && t.generateTestIdentity('member')]) {",
      '  try { call(); errors.push(null); } catch (error) { errors.push(error.name); }',
      '}',
      'process.stdout.write(JSON.stringify(errors));',
    ].join('\n');
    const result = importTestingEntry({ NODE_ENV: 'test', TINYLAND_AUTH_TEST_ADMISSION: 'enabled' }, body);
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual([
      'TestingEntryRefusedError',
      'TestAdmissionDisabledError',
      'TestingEntryRefusedError',
    ]);
  });
});
