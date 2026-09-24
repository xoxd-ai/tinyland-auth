import { readFile, readdir } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const readText = (path: string) => readFile(path, 'utf8');
const release = 'ae836d8400d5784d74af4fecc020f225d1c2d08e';
const candidatePath = 'docs/gf-v4-qualification.candidate.yml';

describe('inert GF v4 qualification source contract', () => {
  it('declares only the exact status-only test and package/typecheck actions', async () => {
    const plan = JSON.parse(await readText('.github/lanes.json'));
    expect(plan).toEqual({
      schema_version: 3,
      actions: {
        'unit-tests': {
          command: 'test',
          targets: ['//:test', '//:release_metadata_test', '//:invitation_authority_test', '//:package_artifact_test'],
          capability: 'rbe-linux-x86_64',
          result: { mode: 'status-only' },
        },
        'package-check': {
          command: 'build',
          targets: ['//:pkg', '//:typecheck'],
          capability: 'rbe-linux-x86_64',
          result: { mode: 'status-only' },
        },
      },
    });
  });

  it('pins the released thin caller without adding execution or publication authority', async () => {
    const candidate = (await readText(candidatePath))
      .split('\n').filter((line) => !line.startsWith('#')).join('\n').trim();
    expect(candidate).toBe(`name: GF v4 qualification

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  id-token: write

jobs:
  qualify:
    if: >-
      github.event_name == 'push' ||
      github.event.pull_request.head.repo.full_name == github.repository
    strategy:
      fail-fast: false
      matrix:
        action: [unit-tests, package-check]
    uses: xoxd-ai/ci-templates/.github/workflows/spoke-ci-v4.yml@${release}
    with:
      action_name: \${{ matrix.action }}`);
  });

  it('keeps the candidate outside the active workflow directory', async () => {
    const entries = await readdir('.github/workflows').catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return [];
      throw error;
    });
    expect(entries.filter((name) => /\.ya?ml$/.test(name))).toEqual([]);
    expect(await readText(candidatePath)).toContain('# INERT SOURCE CANDIDATE');
  });

  it('executes standing release guards against declared source and generated inputs', async () => {
    const build = await readText('BUILD.bazel');
    const metadata = build.match(/js_test\(\s*name = "release_metadata_test",([\s\S]*?)\n\)/)?.[1];
    const invitations = build.match(/js_test\(\s*name = "invitation_authority_test",([\s\S]*?)\n\)/)?.[1];
    expect(metadata).toContain('entry_point = "scripts/check-release-metadata.mjs"');
    for (const input of ['package.json', 'MODULE.bazel', 'BUILD.bazel', 'CHANGELOG.md']) {
      expect(metadata).toContain(`"${input}"`);
    }
    expect(invitations).toContain('entry_point = "scripts/check-invitation-authority.mjs"');
    expect(metadata).toContain('chdir = package_name()');
    expect(invitations).toContain('chdir = package_name()');
    for (const input of [':tinyland_auth_types', ':node_modules/typescript', 'src/index.ts', 'package.json']) {
      expect(invitations).toContain(`"${input}"`);
    }
  });

  it('allows retired workflows to be absent while retaining future YAML callers in test runfiles', async () => {
    const build = await readText('BUILD.bazel');
    const test = build.match(/vitest_bin\.vitest_test\(\s*name = "test",([\s\S]*?)\n\)/)?.[1];
    expect(test).toContain(
      'glob([".github/workflows/*.yml", ".github/workflows/*.yaml"], allow_empty = True)',
    );
  });

  it('retains meaningful package validation without a provider publisher', async () => {
    const build = await readText('BUILD.bazel');
    const artifact = build.match(/js_test\(\s*name = "package_artifact_test",([\s\S]*?)\n\)/)?.[1];
    expect(artifact).toContain('":pkg"');
    expect(artifact).toContain('":node_modules/publint"');
    expect(artifact).toContain('chdir = package_name()');
    expect(build).toContain('scripts/check-invitation-authority.mjs');
    expect(build).toContain('scripts/check-release-metadata.mjs');
    const candidate = await readText(candidatePath);
    expect(candidate).not.toMatch(/packages:\s*write|secrets:|publish_mode:|github_package_name:|npm_publish_mode:|workflow_dispatch:/);
  });
});
