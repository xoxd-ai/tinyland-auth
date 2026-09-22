import { readFile, readdir } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const readText = (path: string) => readFile(path, 'utf8');
const normalizeWhitespace = (value: string) => value.replace(/\s+/g, ' ');

// Extract the version declared inside the top-level module() call of MODULE.bazel.
// Scoped to the module() block so bazel_dep(..., version = ...) lines cannot match.
const extractModuleVersion = (moduleBazel: string): string => {
  const moduleBlock = moduleBazel.match(/module\(([\s\S]*?)\)/);
  if (!moduleBlock) {
    throw new Error('module() declaration not found in MODULE.bazel');
  }
  const version = moduleBlock[1].match(/version\s*=\s*"([^"]+)"/);
  if (!version) {
    throw new Error('version attribute not found in the module() declaration');
  }
  return version[1];
};

// Extract the version declared inside the npm_package() target of BUILD.bazel.
const extractNpmPackageVersion = (buildBazel: string): string => {
  const pkgBlock = buildBazel.match(/npm_package\(([\s\S]*?)\n\)/);
  if (!pkgBlock) {
    throw new Error('npm_package() target not found in BUILD.bazel');
  }
  const version = pkgBlock[1].match(/version\s*=\s*"([^"]+)"/);
  if (!version) {
    throw new Error('version attribute not found in the npm_package() target');
  }
  return version[1];
};

describe('package release authority', () => {
  it('keeps the TypeScript import API under the @tummycrypt scope', async () => {
    const packageJson = JSON.parse(await readText('package.json')) as {
      name?: string;
      publishConfig?: unknown;
      private?: boolean;
    };
    const buildBazel = await readText('BUILD.bazel');

    expect(packageJson.name).toBe('@tummycrypt/tinyland-auth');
    expect(packageJson.publishConfig).toBeUndefined();
    expect(packageJson.private).toBe(true);
    expect(buildBazel).toContain('package = "@tummycrypt/tinyland-auth"');
    expect(buildBazel).toContain('publishable = False');
  });

  it('retires provider workflows without silently activating an unadmitted replacement', async () => {
    const workflows = await readdir('.github/workflows').catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return [];
      throw error;
    });
    expect(workflows.filter(name => /\.ya?ml$/.test(name))).toEqual([]);
    const packageJson = JSON.parse(await readText('package.json'));
    expect(packageJson.publishConfig).toBeUndefined();
    for (const hook of ['prepublish', 'prepublishOnly', 'publish', 'postpublish', 'test:bazel']) {
      expect(packageJson.scripts[hook]).toBeUndefined();
    }
    expect(JSON.stringify(packageJson.scripts)).not.toMatch(/\bnpx\b|\b(?:npm|pnpm)\s+publish\b/);
  });

  it('executes the Bazel test target instead of only building it', async () => {
    const plan = JSON.parse(await readText('.github/lanes.json'));
    expect(plan.actions['unit-tests'].command).toBe('test');
    expect(plan.actions['unit-tests'].targets).toEqual([
      '//:test', '//:release_metadata_test', '//:invitation_authority_test', '//:package_artifact_test',
    ]);
    expect(plan.actions['package-check'].command).toBe('build');
    expect(plan.actions['package-check'].targets).toEqual(['//:pkg', '//:typecheck']);
    const build = await readText('BUILD.bazel');
    expect(build).not.toContain('scripts/ci-bazel-test.sh');
  });

  it('checks release metadata before package validation and publication', async () => {
    const packageJson = JSON.parse(await readText('package.json')) as {
      scripts?: Record<string, string>;
    };
    const guard = await readText('scripts/check-release-metadata.mjs');

    expect(packageJson.scripts?.['check:release-metadata']).toBe(
      'node scripts/check-release-metadata.mjs',
    );
    expect(guard).toContain("await readFile('MODULE.bazel', 'utf8')");
    expect(guard).toContain("await readFile('BUILD.bazel', 'utf8')");
    expect(guard).toContain("await readFile('CHANGELOG.md', 'utf8')");
    expect(guard).toContain("process.env.GITHUB_REF_TYPE === 'tag'");
  });

  it('keeps the packaged version aligned with the MODULE.bazel SSOT', async () => {
    const moduleBazel = await readText('MODULE.bazel');
    const buildBazel = await readText('BUILD.bazel');
    const packageJson = JSON.parse(await readText('package.json')) as { version?: string };

    const moduleVersion = extractModuleVersion(moduleBazel);
    const packagedVersion = extractNpmPackageVersion(buildBazel);

    // MODULE.bazel is the version authority. The npm_package() target and the
    // package.json manifest must both agree with it, or a release ships a
    // version that disagrees with the Bazel-registry SSOT and the git tag.
    expect(packagedVersion).toBe(moduleVersion);
    expect(packageJson.version).toBe(moduleVersion);
  });

  it('checks the actual Bazel package without provider packing or publication', async () => {
    const build = await readText('BUILD.bazel');
    const artifact = build.match(/js_test\(\s*name = "package_artifact_test",([\s\S]*?)\n\)/)?.[1];
    expect(artifact).toContain('entry_point = "scripts/check-package-artifact.mjs"');
    expect(artifact).toContain('args = ["$(rootpath :pkg)"]');
    for (const input of [':pkg', ':node_modules/publint', 'package.json']) {
      expect(artifact).toContain(`"${input}"`);
    }
    const guard = await readText('scripts/check-package-artifact.mjs');
    expect(guard).toContain('publint({ pkgDir: packageDirectory, pack: false })');
    expect(guard).toContain('assert.deepEqual(artifact.exports, source.exports');
    expect(guard).toContain("message.type === 'error'");
    expect(guard).not.toMatch(/(?:spawn|execFile|execSync)\s*\(/);
  });

  it('keeps first-party dependencies out of the package-manager graph', async () => {
    const packageJson = JSON.parse(await readText('package.json'));
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      expect(Object.keys(packageJson[field] ?? {}).filter(name => /^@(tummycrypt|tinyland|tinyland-inc|xoxd-ai)\//.test(name))).toEqual([]);
    }
    const module = await readText('MODULE.bazel');
    expect(module).toContain('name = "tummycrypt_tinyland_auth_npm"');
    expect(module).toContain('pnpm_lock = "//:pnpm-lock.yaml"');
    expect(module).not.toContain('WORKSPACE');
  });

  it('documents BCR-only delivery without claiming pending GF admission', async () => {
    const readme = await readText('README.md');
    const mvpDoc = await readText('docs/tinyland-databaseless-auth-mvp.md');

    for (const document of [readme, mvpDoc]) {
      expect(normalizeWhitespace(document)).toContain('Bzlmod plus the append-only Tinyland BCR is the sole first-party delivery authority');
      expect(normalizeWhitespace(document)).toContain('neither npmjs nor GitHub Packages is a delivery or fallback lane');
      expect(document).toContain('inert');
      expect(document).not.toContain('GitHub Packages mirror');
    }
  });
});
