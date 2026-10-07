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
