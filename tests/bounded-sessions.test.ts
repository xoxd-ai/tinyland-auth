import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SessionManager } from '../src/core/session/index.js';
import { FileStorageAdapter } from '../src/storage/file.js';
import { MemoryStorageAdapter } from '../src/storage/memory.js';
import type { SessionStorage } from '../src/storage/interface.js';
import type { BoundedSessionPolicy, SessionConfig } from '../src/types/config.js';

const directories: string[] = [];
const policy: BoundedSessionPolicy = { maxConcurrentSessions: 10, overflow: 'evict-oldest-created' };
const config: SessionConfig = {
  sessionStrategy: 'bounded', maxConcurrentSessions: 10,
  maxAge: 86_400_000, renewThreshold: 3_600_000, rememberMeDuration: 86_400_000,
  cookieName: 'session', secureCookie: true, sameSite: 'lax', httpOnly: true,
};
const identity = { id: 'alice-id', handle: 'alice', role: 'member' as const };

async function fileFixture() {
  const directory = await fs.mkdtemp(path.join(tmpdir(), 'tinyland-auth-bounded-sessions-'));
  directories.push(directory);
  const authDir = path.relative(process.cwd(), path.join(directory, 'auth'));
  const totpDir = path.relative(process.cwd(), path.join(directory, 'totp'));
  const first = new FileStorageAdapter({ authDir, totpDir });
  const second = new FileStorageAdapter({ authDir: path.join(authDir, '.'), totpDir });
  await first.init();
  return { first, second, filename: path.join(directory, 'auth', 'sessions.json') };
}

afterEach(async () => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  for (const directory of directories.splice(0)) {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

describe.each(['memory', 'file'] as const)('bounded sessions: %s adapter', (kind) => {
  async function fixture() {
    if (kind === 'file') return fileFixture();
    const first = new MemoryStorageAdapter();
    return { first, second: first };
  }

  it('preserves simultaneous sessions and evicts only the oldest created at the configured cap', async () => {
    const { first } = await fixture();
    const manager = new SessionManager({ storage: first, config });
    const sessions = [];
    for (let index = 0; index < 10; index++) {
      const session = await manager.createSession(identity.id, identity);
      await first.updateSession(session.id, { createdAt: new Date(1_700_000_000_000 + index).toISOString() });
      sessions.push(session);
    }
    const other = await first.createSession('bob-id', { id: 'bob-id', handle: 'bob' });
    expect(await manager.getSession(sessions[0].id)).not.toBeNull();
    expect(await manager.getSession(sessions[1].id)).not.toBeNull();
    const newest = await manager.createSession(identity.id, identity);
    const remaining = await first.getSessionsByUser(identity.id);
    expect(remaining).toHaveLength(10);
    expect(remaining.map((session) => session.id)).toEqual([...sessions.slice(1).map((session) => session.id), newest.id]);
    expect(await first.getSession(sessions[0].id)).toBeNull();
    expect(await first.getSession(other.id)).toEqual(other);
  });

  it('uses private ID as deterministic equal-timestamp tie-break and always retains the new session', async () => {
    const { first } = await fixture();
    const sessions = await Promise.all(Array.from({ length: 3 }, () => first.createSession(identity.id, identity)));
    for (const session of sessions) await first.updateSession(session.id, { createdAt: '2020-01-01T00:00:00.000Z' });
    const newest = await first.createSessionWithPolicy(identity.id, identity, undefined, { ...policy, maxConcurrentSessions: 3 });
    const expected = sessions.map((session) => session.id).sort().slice(1);
    expect((await first.getSessionsByUser(identity.id)).map((session) => session.id)).toEqual([...expected, newest.id]);
  });

  it('removes expired owner sessions before enforcing the cap, without deleting another owner', async () => {
    const { first } = await fixture();
    const expired = await first.createSession(identity.id, identity);
    await first.updateSession(expired.id, { expires: '2020-01-01T00:00:00.000Z' });
    const existing = await first.createSession(identity.id, identity);
    const other = await first.createSession('bob-id', { id: 'bob-id' });
    await first.updateSession(other.id, { expires: '2020-01-01T00:00:00.000Z' });
    const newest = await first.createSessionWithPolicy(identity.id, identity, undefined, { ...policy, maxConcurrentSessions: 2 });
    const all = await first.getAllSessions();
    expect(all.map((session) => session.id).sort()).toEqual([existing.id, newest.id, other.id].sort());
  });

  it('serializes concurrent creates at ten without losing another user or duplicating IDs', async () => {
    const { first, second } = await fixture();
    const managers = [first, second].map((storage) => new SessionManager({ storage, config }));
    const other = await first.createSession('bob-id', { id: 'bob-id' });
    const results = await Promise.all(Array.from({ length: 24 }, (_, index) =>
      managers[index % 2].createSession(identity.id, identity)));
    expect(new Set(results.map((session) => session.id)).size).toBe(24);
    const remaining = await first.getSessionsByUser(identity.id);
    expect(remaining).toHaveLength(10);
    expect(remaining.some((session) => session.id === results[23].id)).toBe(true);
    expect(await second.getSession(other.id)).toEqual(other);
  });

  it('keeps revoke-one separate from revoke-all and permits a fresh login after all-session revocation', async () => {
    const { first, second } = await fixture();
    const manager = new SessionManager({ storage: first, config });
    const a = await manager.createSession(identity.id, identity);
    const b = await manager.createSession(identity.id, identity);
    const other = await first.createSession('bob-id', { id: 'bob-id' });
    expect(await manager.removeSession(a.id)).toBe(true);
    expect(await second.getSession(b.id)).not.toBeNull();
    expect(await manager.removeUserSessions(identity.id)).toBe(1);
    expect(await second.getSessionsByUser(identity.id)).toEqual([]);
    expect(await second.getSession(other.id)).toEqual(other);
    const next = await manager.createSession(identity.id, identity);
    expect(await manager.validateSession(next.id)).not.toBeNull();
  });

  it.each([0, -1, 1.5, NaN, Infinity])('rejects invalid cap %s before any storage mutation', async (cap) => {
    const { first } = await fixture();
    const prior = await first.createSession(identity.id, identity);
    const manager = new SessionManager({ storage: first, config: { ...config, maxConcurrentSessions: cap } });
    await expect(manager.createSession(identity.id, identity)).rejects.toThrow('Invalid bounded session policy');
    expect(await first.getAllSessions()).toEqual([prior]);
  });

  it('retains historical single-session behavior unless the strategy is explicitly bounded', async () => {
    const { first } = await fixture();
    const manager = new SessionManager({ storage: first, config: { ...config, sessionStrategy: undefined } });
    const a = await manager.createSession(identity.id, identity);
    const b = await manager.createSession(identity.id, identity);
    expect(await first.getSession(a.id)).toBeNull();
    expect(await first.getSession(b.id)).not.toBeNull();
  });
});

it('fails closed for bounded mode on an adapter without atomic capability', async () => {
  const storage = new MemoryStorageAdapter();
  const prior = await storage.createSession(identity.id, identity);
  Object.defineProperty(storage, 'createSessionWithPolicy', { value: undefined });
  const manager = new SessionManager({ storage: storage as SessionStorage, config });
  await expect(manager.createSession(identity.id, identity)).rejects.toThrow('Storage does not support atomic bounded sessions');
  expect(await storage.getAllSessions()).toEqual([prior]);
});

describe('shared file-session mutation queue', () => {
  it('does not lose simultaneous field updates from separate adapter instances', async () => {
    const { first, second } = await fileFixture();
    const session = await first.createSession(identity.id, identity);
    await Promise.all([
      first.updateSession(session.id, { userAgent: 'updated-agent' }),
      second.updateSession(session.id, { deviceType: 'tablet' }),
      first.updateSession(session.id, { clientIpMasked: 'masked' }),
    ]);
    expect(await second.getSession(session.id)).toMatchObject({ userAgent: 'updated-agent', deviceType: 'tablet', clientIpMasked: 'masked' });
  });

  it('orders revoke, renew, cleanup and bounded-create without resurrecting deleted or expired sessions', async () => {
    const { first, second } = await fileFixture();
    const revoked = await first.createSession(identity.id, identity);
    const retained = await first.createSession(identity.id, identity);
    const expired = await first.createSession(identity.id, identity);
    await first.updateSession(expired.id, { expires: '2020-01-01T00:00:00.000Z' });
    const renewed = new Date(Date.now() + 86_400_000).toISOString();
    const [, , , created] = await Promise.all([
      first.deleteSession(revoked.id),
      second.updateSession(retained.id, { expires: renewed, expiresAt: renewed }),
      first.cleanupExpiredSessions(),
      second.createSessionWithPolicy(identity.id, identity, undefined, policy),
    ]);
    expect((await first.getAllSessions()).map((session) => session.id).sort()).toEqual([retained.id, created.id].sort());
    expect((await first.getSession(retained.id))?.expires).toBe(renewed);
    await Promise.all([
      first.deleteUserSessions(identity.id),
      second.createSessionWithPolicy(identity.id, identity, undefined, policy),
    ]);
    expect(await first.getSessionsByUser(identity.id)).toHaveLength(1);
    expect(await first.getSession(retained.id)).toBeNull();
  });

  it('does not overwrite malformed or duplicate-identity stores', async () => {
    const { first, filename } = await fileFixture();
    const session = await first.createSession(identity.id, identity);
    for (const raw of ['{', '{}', 'null', JSON.stringify([session, session]), JSON.stringify([{ ...session, expires: 'invalid' }])]) {
      await fs.writeFile(filename, raw);
      await expect(first.createSessionWithPolicy(identity.id, identity, undefined, policy)).rejects.toThrow();
      expect(await fs.readFile(filename, 'utf8')).toBe(raw);
    }
  });

  it('preserves prior sessions on failed publication and does not wedge later mutations', async () => {
    const { first, second, filename } = await fileFixture();
    const prior = await first.createSession(identity.id, identity);
    const before = await fs.readFile(filename, 'utf8');
    const rename = vi.spyOn(fs, 'rename').mockRejectedValueOnce(new Error('fixture publication failure'));
    await expect(second.createSessionWithPolicy(identity.id, identity, undefined, { ...policy, maxConcurrentSessions: 1 }))
      .rejects.toThrow('fixture publication failure');
    expect(await fs.readFile(filename, 'utf8')).toBe(before);
    expect(await first.getSession(prior.id)).toEqual(prior);
    rename.mockRestore();
    const replacement = await first.createSessionWithPolicy(identity.id, identity, undefined, { ...policy, maxConcurrentSessions: 1 });
    expect(await second.getAllSessions()).toEqual([replacement]);
  });

  it('does not acknowledge login if directory sync fails after publication', async () => {
    const { first, second, filename } = await fileFixture();
    const prior = await first.createSession(identity.id, identity);
    const nativeOpen = fs.open.bind(fs);
    vi.spyOn(fs, 'open').mockImplementation(async (file, flags, mode) => {
      const handle = await nativeOpen(file, flags, mode);
      if (String(file) === path.dirname(filename)) {
        vi.spyOn(handle, 'sync').mockRejectedValueOnce(new Error('fixture directory sync failure'));
      }
      return handle;
    });
    await expect(second.createSessionWithPolicy(identity.id, identity, undefined, { ...policy, maxConcurrentSessions: 1 }))
      .rejects.toThrow('fixture directory sync failure');
    // Rename already occurred: do not falsely promise rollback of the store.
    const observed = await first.getAllSessions();
    expect(observed).toHaveLength(1);
    expect(observed[0].id).not.toBe(prior.id);
  });
});
