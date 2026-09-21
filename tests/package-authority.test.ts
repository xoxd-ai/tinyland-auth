import { readFile } from 'node:fs/promises';
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
    };
    const buildBazel = await readText('BUILD.bazel');

    expect(packageJson.name).toBe('@tummycrypt/tinyland-auth');
    expect(packageJson.publishConfig).toBeUndefined();
    expect(buildBazel).toContain('package = "@tummycrypt/tinyland-auth"');
  });

  it('keeps npmjs publication disabled in package workflows', async () => {
    const workflowPaths = ['.github/workflows/ci.yml', '.github/workflows/publish.yml'];

    for (const workflowPath of workflowPaths) {
      const workflow = await readText(workflowPath);

      expect(workflow).toContain('runner_mode: repo_owned');
      expect(workflow).toContain('runner_labels_json: ${{ vars.PRIMARY_LINUX_RUNNER_LABELS_JSON }}');
      expect(workflow).toContain('metadata_check_command: pnpm check:release-metadata');
      expect(workflow).toContain('unit_test_command: pnpm test && pnpm test:bazel');
      expect(workflow).toContain(
        'package_check_command: pnpm check:invitation-authority && pnpm check:package',
      );
      expect(workflow).toContain('bazel_targets: "//:pkg //:test //:typecheck"');
      expect(workflow).toContain('npm_publish_mode: disabled');
      expect(workflow).not.toContain('github_package_name');
    }
  });

  it('executes the Bazel test target instead of only building it', async () => {
    const packageJson = JSON.parse(await readText('package.json')) as {
      scripts?: Record<string, string>;
    };
    const bazelTestScript = await readText('scripts/ci-bazel-test.sh');

    expect(packageJson.scripts?.['test:bazel']).toBe('bash scripts/ci-bazel-test.sh');
    expect(bazelTestScript).toContain(
      'npx --yes @bazel/bazelisk test //:test //:typecheck --test_output=errors',
    );
    expect(bazelTestScript).not.toMatch(/@bazel\/bazelisk build\b/);
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

  it('documents Bazel-first release authority for consumers', async () => {
    const readme = await readText('README.md');
    const mvpDoc = await readText('docs/tinyland-databaseless-auth-mvp.md');

    expect(readme).toContain('npmjs publication is disabled');
    expect(readme).toContain('GitHub Packages mirror');
    expect(readme).toContain('Tinyland Bazel registry');
    expect(readme).toContain('repo-owned GloriousFlywheel runner lane');
    expect(mvpDoc).toContain('`//:pkg //:test //:typecheck`');
    expect(mvpDoc).toContain('repo-owned GloriousFlywheel runner lane');
    expect(normalizeWhitespace(mvpDoc)).toContain('npmjs publication is disabled');
  });
});
