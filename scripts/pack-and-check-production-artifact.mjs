#!/usr/bin/env node
// Packs this package exactly as `pnpm publish` would (`pnpm pack`), extracts
// the tarball, and runs check-production-artifact.mjs against the extracted
// package. Run after `pnpm build`. Bazel runs the same check against `//:pkg`
// (`//:production_artifact_test`).

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const work = mkdtempSync(join(tmpdir(), 'tinyland-auth-pack-'));

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit', ...options });
  if (result.status !== 0) {
    rmSync(work, { recursive: true, force: true });
    process.exit(result.status ?? 1);
  }
}

run('pnpm', ['pack', '--pack-destination', work], { stdio: ['ignore', 'ignore', 'inherit'] });
const tarball = readdirSync(work).find((name) => name.endsWith('.tgz'));
if (!tarball) {
  console.error(`pnpm pack produced no tarball in ${work}`);
  process.exit(1);
}
run('tar', ['-xzf', join(work, tarball), '-C', work]);
console.log(`checking packed tarball ${tarball}`);
run(process.execPath, [join(here, 'check-production-artifact.mjs'), join(work, 'package')]);
rmSync(work, { recursive: true, force: true });
