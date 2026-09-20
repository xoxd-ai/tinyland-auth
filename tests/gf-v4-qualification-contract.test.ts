import { readFile, readdir } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const readText = (path: string) => readFile(path, 'utf8');
const release = '32e39ced0008edf4564ebeb173a5e8fbf069e28f';
const candidatePath = 'docs/gf-v4-qualification.candidate.yml';

describe('inert GF v4 qualification source contract', () => {
  it('declares only the exact status-only test and package/typecheck actions', async () => {
    const plan = JSON.parse(await readText('.github/lanes.json'));
    expect(plan).toEqual({
      schema_version: 3,
      actions: {
        'unit-tests': {
          command: 'test',
          targets: ['//:test', '//:release_metadata_test', '//:invitation_authority_test'],
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
    const workflows = (await readdir('.github/workflows')).filter((name) => /\.ya?ml$/.test(name)).sort();
    expect(workflows).toEqual(['ci.yml', 'publish.yml']);
    for (const name of workflows) {
      expect(await readText(`.github/workflows/${name}`)).not.toContain('spoke-ci-v4.yml');
    }
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
    for (const input of [':tinyland_auth', ':node_modules/typescript', 'src/index.ts', 'package.json']) {
      expect(invitations).toContain(`"${input}"`);
    }
    expect(build).toContain('glob([".github/workflows/*.yml", ".github/workflows/*.yaml"])');
  });

  it('retains the existing release gates rather than treating status as publication', async () => {
    for (const path of ['.github/workflows/ci.yml', '.github/workflows/publish.yml']) {
      const workflow = await readText(path);
      expect(workflow).toContain('metadata_check_command: pnpm check:release-metadata');
      expect(workflow).toContain('package_check_command: pnpm check:invitation-authority && pnpm check:package');
      expect(workflow).toContain('npm_publish_mode: disabled');
    }
  });
});
