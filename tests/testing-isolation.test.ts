import { readFile, readdir } from 'node:fs/promises';
import { dirname, join, normalize } from 'node:path';
import { describe, expect, it } from 'vitest';
import * as pkg from '../src/index.js';
import * as testing from '../src/testing/index.js';

// RP2 / RS5: no test-only admission path may be reachable from a production
// entry point. The harness lives under src/testing, is compiled only by
// tsconfig.testing.json into dist-testing/, and is not exported or published.
// These source-level guards prove no public entry point reaches it, directly
// or transitively, and that the build configuration keeps it out of dist/.
// tests/production-artifact.test.ts proves the same on built output.

const TESTING_DIR = normalize('src/testing/');

const importSpecifiers = (source: string): string[] => {
  const withoutComments = source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
  const specifiers: string[] = [];
  const patterns = [
    /\b(?:import|export)\s+(?:type\s+)?[^'"`;]*?\bfrom\s*['"]([^'"]+)['"]/g,
    /\bimport\s*['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of withoutComments.matchAll(pattern)) {
      specifiers.push(match[1]);
    }
  }
  return specifiers;
};

const toSourcePath = (from: string, specifier: string): string =>
  normalize(join(dirname(from), specifier)).replace(/\.js$/, '.ts');

async function reachableSources(entry: string): Promise<Set<string>> {
  const seen = new Set<string>();
  const queue = [normalize(entry)];
  while (queue.length > 0) {
    const current = queue.pop() as string;
    if (seen.has(current)) continue;
    seen.add(current);
    const source = await readFile(current, 'utf8');
    for (const specifier of importSpecifiers(source)) {
      if (!specifier.startsWith('.')) continue;
      queue.push(toSourcePath(current, specifier));
    }
  }
  return seen;
}

const distToSource = (distPath: string): string =>
  normalize(distPath.replace(/^\.\/dist\//, 'src/').replace(/\.js$/, '.ts'));

async function allSources(dir = 'src'): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await allSources(full)));
    else if (entry.name.endsWith('.ts')) out.push(normalize(full));
  }
  return out;
}

type ExportTarget = { import: string; types: string };

describe('test-only seams stay off the production surface (RP2, RS5)', () => {
  it('exports and publishes no testing entry', async () => {
    const packageJson = JSON.parse(await readFile('package.json', 'utf8')) as {
      exports: Record<string, ExportTarget>;
      files: string[];
    };
    expect(Object.keys(packageJson.exports).filter((subpath) => /testing/i.test(subpath))).toEqual([]);
    for (const [subpath, target] of Object.entries(packageJson.exports)) {
      expect(JSON.stringify(target), subpath).not.toMatch(/testing/i);
      expect(distToSource(target.import).startsWith(TESTING_DIR), subpath).toBe(false);
    }
    expect(packageJson.files).toEqual(['dist', 'README.md']);
  });

  it('keeps src/testing out of the production build configuration', async () => {
    const tsconfig = JSON.parse(await readFile('tsconfig.json', 'utf8')) as {
      compilerOptions: { outDir: string };
      exclude: string[];
    };
    expect(tsconfig.compilerOptions.outDir).toBe('./dist');
    expect(tsconfig.exclude).toContain('src/testing/**');

    const testingConfig = JSON.parse(await readFile('tsconfig.testing.json', 'utf8')) as {
      compilerOptions: { outDir: string };
    };
    expect(testingConfig.compilerOptions.outDir).toBe('./dist-testing');
    expect(await readFile('.gitignore', 'utf8')).toContain('dist-testing/');

    const buildBazel = await readFile('BUILD.bazel', 'utf8');
    const productionTarget =
      buildBazel.match(/ts_project\(\s*name = "tinyland_auth",[\s\S]*?\n\)/)?.[0] ?? '';
    expect(productionTarget).toContain('"src/testing/**"');
    expect(buildBazel).toContain('name = "production_artifact_test"');
    expect(await readFile('scripts/ci-bazel-test.sh', 'utf8')).toContain('//:production_artifact_test');
  });

  it('reaches src/testing from no public entry point, even transitively', async () => {
    const packageJson = JSON.parse(await readFile('package.json', 'utf8')) as {
      exports: Record<string, { import: string }>;
    };
    const productionEntries = Object.entries(packageJson.exports);
    expect(productionEntries.length).toBeGreaterThanOrEqual(9);

    for (const [subpath, target] of productionEntries) {
      const reachable = await reachableSources(distToSource(target.import));
      const leaked = [...reachable].filter((path) => path.startsWith(TESTING_DIR));
      expect(leaked, `${subpath} reaches the testing module`).toEqual([]);
      // Sanity: the walker really followed imports from this entry.
      expect(reachable.size, `${subpath} import graph`).toBeGreaterThan(0);
    }
    const indexGraph = await reachableSources('src/index.ts');
    expect(indexGraph.has(normalize('src/core/totp/index.ts'))).toBe(true);
    expect(indexGraph.has(normalize('src/totp/otplib-compat.ts'))).toBe(true);
    expect(indexGraph.has(normalize('src/core/seams/index.ts'))).toBe(true);
  });

  it('only src/testing imports the seam writer, and no entry re-exports the seam module', async () => {
    const writers: string[] = [];
    for (const path of await allSources()) {
      const source = await readFile(path, 'utf8');
      if (/\binstallSeams\b/.test(source) && path !== normalize('src/core/seams/index.ts')) {
        writers.push(path);
      }
    }
    expect(writers).toEqual([normalize('src/testing/index.ts')]);

    const packageJson = JSON.parse(await readFile('package.json', 'utf8')) as {
      exports: Record<string, { import: string }>;
    };
    for (const [subpath, target] of Object.entries(packageJson.exports)) {
      const entrySource = await readFile(distToSource(target.import), 'utf8');
      expect(entrySource, subpath).not.toMatch(/core\/seams/);
    }
  });

  it('detects a leak if one is introduced (walker self-test)', () => {
    expect(importSpecifiers(`export * from './testing/index.js';`)).toEqual(['./testing/index.js']);
    expect(importSpecifiers(`const m = await import("../testing/index.js");`)).toEqual([
      '../testing/index.js',
    ]);
    expect(importSpecifiers(`import type { A } from '../testing/index.js';`)).toEqual([
      '../testing/index.js',
    ]);
    expect(importSpecifiers(`// import x from './testing/index.js'`)).toEqual([]);
    expect(toSourcePath('src/index.ts', './testing/index.js').startsWith(TESTING_DIR)).toBe(true);
  });

  it('exports no harness or seam symbol from the package index', () => {
    const surface = Object.keys(pkg as Record<string, unknown>);
    const harness = Object.keys(testing as Record<string, unknown>);
    expect(harness).toContain('createTestAdmissionIssuer');
    expect(harness).toContain('createTestTOTPService');
    expect(surface.filter((name) => harness.includes(name))).toEqual([]);
    expect(
      surface.filter((name) => /test.?admission|manualclock|deterministic|seam|clock|verifier/i.test(name)),
    ).toEqual([]);
  });

  it('never reads the admission opt-in or the sentinel outside the testing module', async () => {
    const indexGraph = await reachableSources('src/index.ts');
    for (const path of indexGraph) {
      const source = await readFile(path, 'utf8');
      expect(source.includes('TINYLAND_AUTH_TEST_ADMISSION'), path).toBe(false);
      expect(source.includes(testing.TESTING_ENTRY_SENTINEL), path).toBe(false);
    }
  });
});
