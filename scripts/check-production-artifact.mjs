#!/usr/bin/env node
// RS5 / RS6 production-artifact exclusion check (TIN-5766, RP2).
//
// Usage: node scripts/check-production-artifact.mjs <package-dir>
//
// <package-dir> is a built package as it is published: Bazel `//:pkg`, an
// extracted `pnpm pack` tarball, or an emulation of one. The check fails if
// any of the following holds:
//
//   1. the manifest exposes a testing entry (any export key or target that
//      names `testing`);
//   2. the package ships a `testing` / `dist-testing` path;
//   3. any shipped code file contains a testing-entry symbol, the unique
//      testing sentinel, or a removed RS6 bypass name;
//   4. a production Vite (Rolldown) SSR bundle that inlines EVERY public entry
//      point contains a testing symbol, the sentinel, a removed RS6 name, or
//      the internal seam writer;
//   5. a production bundle, or Node, can resolve the `./testing` subpath.
//
// It also asserts the bundle contains known production symbols, so a clean
// result cannot come from an empty bundle.

import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { isBuiltin } from 'node:module';
import { tmpdir } from 'node:os';
import { join, relative, resolve, sep } from 'node:path';

// A production bundle is what is under test: force the production mode before
// Vite is loaded, so its `development|production` resolve condition and
// `process.env.NODE_ENV` replacement match a real release build.
process.env.NODE_ENV = 'production';

const TESTING_SENTINEL = 'tinyland-auth-testing-entry-5a9aa858497cf8b557fcbb77';

// Exported names of src/testing. None may appear in production code.
const TESTING_SYMBOLS = [
  TESTING_SENTINEL,
  'TESTING_ENTRY_SENTINEL',
  'TINYLAND_AUTH_TEST_ADMISSION',
  'TestAdmissionIssuer',
  'createTestAdmissionIssuer',
  'TestAdmissionDisabledError',
  'TestingEntryRefusedError',
  'assertTestAdmissionAllowed',
  'isTestAdmissionAllowed',
  'assertTestEnvironment',
  'generateTestIdentity',
  'createManualClock',
  'createDeterministicBackupCodeGenerator',
  'createTestTOTPService',
  'createTestSessionManager',
  'createTestBootstrapService',
];

// Names removed from the production entry by RS6. None may come back.
const REMOVED_RS6_NAMES = [
  'devMode',
  'testCode',
  'TotpVerifier',
  'otplibTotpVerifier',
  // mTLS development auto-pass removed in 1.0.0 (RP2): no caller or host may
  // switch certificate checks off.
  'isDevelopment',
  'detectDevelopment',
  'dev-mode-no-cert',
  // Caller-injected first-admin TOTP verifier removed in 1.0.0 (RS6/RP2):
  // BootstrapService verifies the code itself.
  'verifyTOTP',
];

// Internal seam writer: shipped in dist/core/seams (unreachable through the
// exports map) but never referenced by production code, so it must be
// tree-shaken out of any production bundle.
const BUNDLE_ONLY_FORBIDDEN = ['installSeams'];

// Proof the bundle really contains the production surface.
const REQUIRED_IN_BUNDLE = ['TOTPService', 'createTOTPService', 'BootstrapService', 'SessionManager'];

const CODE_FILE = /\.(?:[cm]?js|d\.[cm]?ts|json)$/;

const failures = [];
const fail = (message) => failures.push(message);

function walk(dir, base = dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules') continue;
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full, base));
    else out.push(relative(base, full).split(sep).join('/'));
  }
  return out;
}

function scanText(label, text, names) {
  for (const name of names) {
    if (text.includes(name)) fail(`${label} contains ${JSON.stringify(name)}`);
  }
}

const pkgArg = process.argv[2];
if (!pkgArg) {
  console.error('usage: check-production-artifact.mjs <package-dir>');
  process.exit(2);
}
const pkgDir = realpathSync(resolve(pkgArg));
const manifest = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'));
const exportsMap = manifest.exports ?? {};

// 1. Manifest.
for (const [subpath, target] of Object.entries(exportsMap)) {
  if (/testing/i.test(subpath) || /testing/i.test(JSON.stringify(target))) {
    fail(`package.json exports a testing entry: ${subpath} -> ${JSON.stringify(target)}`);
  }
}
if (/testing/i.test(JSON.stringify(manifest.files ?? []))) {
  fail(`package.json "files" names a testing path: ${JSON.stringify(manifest.files)}`);
}

// 2 and 3. Shipped files.
const shipped = walk(pkgDir);
for (const file of shipped) {
  if (/(^|\/)(testing|dist-testing)(\/|$)/.test(file)) fail(`package ships a testing path: ${file}`);
  if (CODE_FILE.test(file)) {
    const text = readFileSync(join(pkgDir, file), 'utf8');
    scanText(`shipped file ${file}`, text, TESTING_SYMBOLS);
    if (file !== 'package.json') scanText(`shipped file ${file}`, text, REMOVED_RS6_NAMES);
  }
}

// 4 and 5. Production bundles.
const { build } = await import('vite');

const work = mkdtempSync(join(tmpdir(), 'tinyland-auth-artifact-'));
const scope = join(work, 'node_modules', '@tummycrypt');
mkdirSync(scope, { recursive: true });
symlinkSync(pkgDir, join(scope, 'tinyland-auth'), 'dir');

const runtimeDeps = Object.keys({
  ...(manifest.dependencies ?? {}),
  ...(manifest.peerDependencies ?? {}),
});
const external = (id) =>
  isBuiltin(id) || runtimeDeps.some((dep) => id === dep || id.startsWith(`${dep}/`));

const publicSpecifiers = Object.keys(exportsMap).map((subpath) =>
  subpath === '.' ? '@tummycrypt/tinyland-auth' : `@tummycrypt/tinyland-auth/${subpath.slice(2)}`,
);

async function bundle(name, source) {
  const entry = join(work, `${name}.mjs`);
  writeFileSync(entry, source);
  const outDir = join(work, `out-${name}`);
  await build({
    configFile: false,
    root: work,
    mode: 'production',
    logLevel: 'silent',
    ssr: { noExternal: ['@tummycrypt/tinyland-auth'], target: 'node' },
    build: {
      ssr: entry,
      outDir,
      emptyOutDir: true,
      minify: false,
      sourcemap: false,
      rolldownOptions: { external },
    },
  });
  return walk(outDir)
    .map((file) => readFileSync(join(outDir, file), 'utf8'))
    .join('\n');
}

let bundleBytes = 0;
try {
  const allEntries = publicSpecifiers
    .map((specifier, index) => `export * as entry${index} from ${JSON.stringify(specifier)};`)
    .join('\n');
  const output = await bundle('all-public-entries', `${allEntries}\n`);
  bundleBytes = Buffer.byteLength(output);
  scanText('production bundle', output, [
    ...TESTING_SYMBOLS,
    ...REMOVED_RS6_NAMES,
    ...BUNDLE_ONLY_FORBIDDEN,
  ]);
  for (const name of REQUIRED_IN_BUNDLE) {
    if (!output.includes(name)) fail(`production bundle is missing ${name}; the check would be vacuous`);
  }
} catch (error) {
  fail(`production bundle of the public entries failed: ${error?.message ?? error}`);
}

try {
  await bundle('testing-subpath', `export * from '@tummycrypt/tinyland-auth/testing';\n`);
  fail('a production bundle resolved @tummycrypt/tinyland-auth/testing');
} catch {
  // Expected: the subpath is not exported.
}

for (const conditions of [[], ['--conditions=test'], ['--conditions=development']]) {
  const probe = spawnSync(
    process.execPath,
    [
      ...conditions,
      '--input-type=module',
      '-e',
      "await import('@tummycrypt/tinyland-auth/testing');",
    ],
    { cwd: work, env: { ...process.env, NODE_ENV: 'test' }, encoding: 'utf8' },
  );
  const label = conditions.join(' ') || 'default conditions';
  if (probe.status === 0) {
    fail(`Node resolved @tummycrypt/tinyland-auth/testing (${label})`);
  } else if (!/ERR_PACKAGE_PATH_NOT_EXPORTED/.test(probe.stderr)) {
    fail(`Node refused ./testing (${label}) for an unexpected reason: ${probe.stderr.trim().split('\n')[0]}`);
  }
}

rmSync(work, { recursive: true, force: true });

if (failures.length > 0) {
  for (const failure of failures) console.error(`production artifact error: ${failure}`);
  process.exit(1);
}

console.log(
  `production artifact clean: ${manifest.name}@${manifest.version}, ${shipped.length} files, ` +
    `${publicSpecifiers.length} entry points bundled (${bundleBytes} bytes), ./testing unresolvable`,
);
