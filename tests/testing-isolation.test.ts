import { readFile } from 'node:fs/promises';
import { dirname, join, normalize } from 'node:path';
import { describe, expect, it } from 'vitest';
import * as pkg from '../src/index.js';
import * as testing from '../src/testing/index.js';

// RP2: no test-only admission path may be reachable from a production entry
// point. The harness seams live under src/testing and are published only as
// the explicit "./testing" subpath. These guards prove that no other public
// entry point reaches that module, directly or transitively, so a consumer
// bundle carries it only when the consumer imports the subpath by name.

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

describe('test-only seams stay off the production surface (RP2)', () => {
  it('publishes the harness only under the explicit ./testing subpath', async () => {
    const packageJson = JSON.parse(await readFile('package.json', 'utf8')) as {
      exports: Record<string, { import: string; types: string }>;
    };
    const testingSubpaths = Object.entries(packageJson.exports).filter(([, target]) =>
      distToSource(target.import).startsWith(TESTING_DIR),
    );
    expect(testingSubpaths.map(([subpath]) => subpath)).toEqual(['./testing']);
    expect(packageJson.exports['./testing'].import).toBe('./dist/testing/index.js');
  });

  it('reaches src/testing from no other public entry point, even transitively', async () => {
    const packageJson = JSON.parse(await readFile('package.json', 'utf8')) as {
      exports: Record<string, { import: string }>;
    };
    const productionEntries = Object.entries(packageJson.exports).filter(
      ([subpath]) => subpath !== './testing',
    );
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

  it('exports no harness symbol from the package index', () => {
    const surface = Object.keys(pkg as Record<string, unknown>);
    const harness = Object.keys(testing as Record<string, unknown>);
    expect(harness).toContain('createTestAdmissionIssuer');
    expect(surface.filter((name) => harness.includes(name))).toEqual([]);
    expect(surface.filter((name) => /test.?admission|manualclock|deterministic/i.test(name))).toEqual([]);
  });

  it('never reads the admission opt-in outside the testing module', async () => {
    const indexGraph = await reachableSources('src/index.ts');
    for (const path of indexGraph) {
      const source = await readFile(path, 'utf8');
      expect(source.includes('TINYLAND_AUTH_TEST_ADMISSION'), path).toBe(false);
    }
  });
});
