import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { publint } from 'publint';

// Run as //:package_artifact_test with the real //:pkg directory in runfiles.
// There is no source/dist fallback, package-manager packing or publication.
assert.equal(process.argv.length, 3, 'Expected exactly one Bazel package directory');
const packageDirectory = path.resolve(process.argv[2]);
const source = JSON.parse(await readFile('package.json', 'utf8'));
const artifact = JSON.parse(await readFile(path.join(packageDirectory, 'package.json'), 'utf8'));

assert.equal(artifact.name, '@tummycrypt/tinyland-auth');
assert.equal(artifact.name, source.name);
assert.equal(artifact.version, source.version);
assert.equal(artifact.type, 'module');
assert.equal(artifact.private, true, 'Provider publication must remain blocked');
assert.equal(artifact.publishConfig, undefined, 'Provider publication configuration is retired');
assert.deepEqual(artifact.exports, source.exports, 'Bazel package must preserve every public export');
for (const field of ['main', 'module', 'types', 'engines', 'peerDependenciesMeta']) {
  assert.deepEqual(artifact[field], source[field], `Bazel package must preserve ${field}`);
}
assert.deepEqual(artifact.dependencies, source.dependencies);
assert.deepEqual(artifact.peerDependencies, source.peerDependencies);

const files = new Set(['README.md', artifact.main, artifact.module, artifact.types]);
for (const [subpath, entry] of Object.entries(artifact.exports)) {
  assert.doesNotMatch(subpath, /invitation|invite/i, 'Auth must not expose invitation authority');
  assert.equal(typeof entry.types, 'string', `${subpath} requires generated types`);
  assert.equal(typeof entry.import, 'string', `${subpath} requires generated ESM`);
  files.add(entry.types);
  files.add(entry.import);
}
for (const file of files) {
  assert.equal(typeof file, 'string');
  const relative = path.relative(packageDirectory, path.resolve(packageDirectory, file));
  assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative), 'Export must stay inside package');
  const information = await stat(path.join(packageDirectory, relative));
  assert.ok(information.isFile() && information.size > 0, `Missing or empty package file: ${relative}`);
}

// Import the Bazel-produced server subpath in plain Node. A stray client-rune
// re-export would execute `$state` here and fail instead of being hidden by a
// Svelte/Vitest transform or by tests importing implementation files directly.
const serverEntry = artifact.exports['./sveltekit/server'];
assert.ok(serverEntry, 'Missing server-only SvelteKit export');
const server = await import(pathToFileURL(path.join(packageDirectory, serverEntry.import)).href);
assert.equal(typeof server.createCSRFHandle, 'function');
assert.equal(typeof server.requireContentEditPermission, 'function');
assert.equal(typeof server.requireAuth, 'function');
assert.equal('csrfStore' in server, false, 'Server entry must not expose the client CSRF store');
assert.equal('createCSRFStore' in server, false, 'Server entry must not expose client rune factories');
assert.throws(
  () => server.requireContentEditPermission({ id: 'reader', role: 'viewer' }, { authorId: 'another-owner' }),
  { status: 403 },
  'Server entry must retain SvelteKit HTTP 403 guard semantics',
);

// //:pkg is already the complete Bazel-produced directory. pack:false checks
// those exact bytes without spawning npm/pnpm or trusting a second pack result.
const { messages } = await publint({ pkgDir: packageDirectory, pack: false });
for (const message of messages) {
  console.log(`publint ${message.type}: ${message.code} at ${message.path.join('.')}`);
}
assert.equal(messages.filter(message => message.type === 'error').length, 0, 'Bazel package failed publint');
console.log(`Bazel package artifact aligned at ${artifact.version}; ${files.size} declared files checked`);
