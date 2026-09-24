import { createHmac } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  FileActionStepUpStore, type ActionStepUpBinding, type ActionStepUpIdentity,
} from '../src/storage/action-step-up.js';

const KEY = 'test-only-existing-auth-key-with-more-than-32-bytes';
const START = Date.parse('2026-09-24T00:00:00.000Z');
const directories: string[] = [];

function hmac(value: string): string {
  return createHmac('sha256', KEY).update(value).digest('hex');
}

function binding(): ActionStepUpBinding {
  return {
    userId: 'owner-secret-user',
    sessionBinding: hmac('session:opaque-private-bearer'),
    credentialBinding: hmac('credential:current-password-and-provider'),
    authorityBinding: hmac('authority:role-and-permissions'),
    factorBinding: hmac('factor:generation-one'),
    action: 'federation.activate', resourceKind: 'user', resourceId: 'owner-secret-user',
    intentDigest: hmac('validated:{enabled:true}'),
    targetDigest: hmac('target:disabled-revision-0'),
  };
}

async function fixture(overrides: { ttlMs?: number; maxRecords?: number; maxFailures?: number; signingKey?: () => string } = {}) {
  const directory = await fs.mkdtemp(path.join(tmpdir(), 'tinyland-step-up-'));
  directories.push(directory);
  let now = START;
  const config = { directory, signingKey: overrides.signingKey ?? (() => KEY), now: () => now,
    ttlMs: overrides.ttlMs, maxRecords: overrides.maxRecords, maxFailures: overrides.maxFailures };
  return {
    directory, store: new FileActionStepUpStore(config),
    fresh: () => new FileActionStepUpStore(config),
    setTime: (value: number) => { now = value; },
    files: async () => (await fs.readdir(directory)).filter((name) => name.endsWith('.json')),
  };
}

afterEach(async () => {
  vi.restoreAllMocks();
  for (const directory of directories.splice(0)) await fs.rm(directory, { recursive: true, force: true });
});

describe('file-backed action-bound TOTP step-up', () => {
  it('rejects correctly sealed but structurally invalid records before factor verification', async () => {
    const f = await fixture();
    const bound = binding();
    const challenge = await f.store.issue(bound);
    const filename = path.join(f.directory, (await f.files())[0]);
    const original = await fs.readFile(filename, 'utf8');
    const pending = JSON.parse(original).record;
    const verified = { ...pending, state: 'verified', verifiedAt: START, permitDigest: hmac('permit') };
    const consumed = { ...verified, state: 'consumed', consumedAt: START, receiptDigest: hmac('receipt') };
    const invalid = [
      { ...pending, action: 1 }, { ...pending, state: 'unknown' },
      { ...pending, createdAt: String(START) }, { ...pending, expiresAt: String(START + 1000) },
      { ...pending, failures: '0' }, { ...pending, extra: true },
      { ...verified, verifiedAt: String(START) }, { ...verified, verifiedAt: pending.expiresAt },
      { ...consumed, consumedAt: String(START) }, { ...consumed, consumedAt: START - 1 },
      { ...consumed, receiptDigest: null },
    ];
    const verifier = vi.fn(async () => true);
    for (const record of invalid) {
      const seal = createHmac('sha256', KEY).update('tinyland-auth:action-step-up:seal:v1\0')
        .update(JSON.stringify(record)).digest('hex');
      const bytes = JSON.stringify({ version: 1, record, seal });
      await fs.writeFile(filename, bytes);
      await expect(f.fresh().verify({ challengeId: challenge.challengeId, identity: bound }, verifier))
        .rejects.toMatchObject({ code: 'INVALID' });
      expect(await fs.readFile(filename, 'utf8')).toBe(bytes);
    }
    expect(verifier).not.toHaveBeenCalled();
    await fs.writeFile(filename, original);
    await expect(f.fresh().verify({ challengeId: challenge.challengeId, identity: bound }, verifier))
      .resolves.toMatchObject(challenge);
    expect(verifier).toHaveBeenCalledOnce();
  });

  it('seals private pending, verified and consumed records without raw references, bearer, resource or intent', async () => {
    const f = await fixture();
    const bound = binding();
    const challenge = await f.store.issue(bound);
    const files = await f.files();
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/^[a-f0-9]{64}\.json$/);
    const rawPending = await fs.readFile(path.join(f.directory, files[0]), 'utf8');
    for (const secret of [challenge.challengeId, bound.userId, bound.resourceId, 'opaque-private-bearer', 'enabled:true']) {
      expect(rawPending).not.toContain(secret);
    }
    const verifyFactor = vi.fn(async () => true);
    const permit = await f.store.verify({ challengeId: challenge.challengeId, identity: bound }, verifyFactor);
    expect(permit).toMatchObject(challenge);
    expect(permit.permitId).toMatch(/^[A-Za-z0-9_-]{43}$/);
    await expect(f.fresh().verify({ challengeId: challenge.challengeId, identity: bound }, verifyFactor))
      .rejects.toMatchObject({ code: 'CONFLICT' });
    expect(verifyFactor).toHaveBeenCalledTimes(1);
    const receipt = await f.fresh().consume({ challengeId: challenge.challengeId, permitId: permit.permitId, binding: bound });
    expect(receipt).toMatchObject({ userId: bound.userId, factorBinding: bound.factorBinding,
      action: 'federation.activate', resourceId: bound.resourceId });
    expect(receipt.receiptId).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const rawConsumed = await fs.readFile(path.join(f.directory, files[0]), 'utf8');
    expect(rawConsumed).not.toContain(receipt.receiptId);
    expect(rawConsumed).not.toContain(permit.permitId);
    await expect(f.fresh().consume({ challengeId: challenge.challengeId, permitId: permit.permitId, binding: bound }))
      .rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('requires current identity for verification and exact action, resource, intent and target at consume', async () => {
    const f = await fixture();
    const bound = binding();
    const challenge = await f.store.issue(bound);
    const verifier = vi.fn(async () => true);
    for (const field of ['userId', 'sessionBinding', 'credentialBinding', 'authorityBinding', 'factorBinding'] as const) {
      const changed: ActionStepUpIdentity = { ...bound, [field]: field === 'userId' ? 'another-owner' : hmac(`changed:${field}`) };
      await expect(f.store.verify({ challengeId: challenge.challengeId, identity: changed }, verifier))
        .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    }
    expect(verifier).not.toHaveBeenCalled();
    await expect(f.store.consume({ challengeId: challenge.challengeId, permitId: 'A'.repeat(43), binding: bound }))
      .rejects.toMatchObject({ code: 'CONFLICT' });
    const permit = await f.store.verify({ challengeId: challenge.challengeId, identity: bound }, verifier);
    const changes: ActionStepUpBinding[] = [
      { ...bound, action: 'user.remove' },
      { ...bound, resourceKind: 'invitation' },
      { ...bound, resourceId: 'another-owner' },
      { ...bound, intentDigest: hmac('changed-intent') },
      { ...bound, targetDigest: hmac('changed-target') },
      { ...bound, authorityBinding: hmac('changed-privileges') },
      { ...bound, factorBinding: hmac('replacement-factor') },
    ];
    for (const changed of changes) {
      await expect(f.store.consume({ challengeId: challenge.challengeId, permitId: permit.permitId, binding: changed }))
        .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    }
    await expect(f.store.consume({ challengeId: challenge.challengeId, permitId: 'B'.repeat(43), binding: bound }))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    await expect(f.store.consume({ challengeId: challenge.challengeId, permitId: permit.permitId, binding: bound }))
      .resolves.toMatchObject({ action: bound.action });
  });

  it('bounds bad-code attempts and never invokes a factor callback after the budget is spent', async () => {
    const f = await fixture({ maxFailures: 2 });
    const bound = binding();
    const challenge = await f.store.issue(bound);
    const bad = vi.fn(async () => false);
    for (let attempt = 0; attempt < 2; attempt++) {
      await expect(f.fresh().verify({ challengeId: challenge.challengeId, identity: bound }, bad))
        .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    }
    await expect(f.store.verify({ challengeId: challenge.challengeId, identity: bound }, bad))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(bad).toHaveBeenCalledTimes(2);
  });

  it('never extends five-minute absolute expiry and prunes only expired records at bounded capacity', async () => {
    const f = await fixture({ ttlMs: 1_000, maxRecords: 1 });
    const bound = binding();
    const first = await f.store.issue(bound);
    await expect(f.store.issue(bound)).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    f.setTime(START + 1_000);
    await expect(f.store.verify({ challengeId: first.challengeId, identity: bound }, async () => true))
      .rejects.toMatchObject({ code: 'EXPIRED' });
    const second = await f.store.issue(bound);
    expect(second.challengeId).not.toBe(first.challengeId);
    expect(await f.files()).toHaveLength(1);
    await expect(f.store.consume({ challengeId: second.challengeId, permitId: 'A'.repeat(43), binding: bound }))
      .rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(f.store.verify({ challengeId: first.challengeId, identity: bound }, async () => true))
      .rejects.toMatchObject({ code: 'INVALID' });
  });

  it('fails closed on unavailable signing custody and on a forged sealed record', async () => {
    const unavailable = await fixture({ signingKey: () => 'short' });
    await expect(unavailable.store.issue(binding())).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(await unavailable.files()).toHaveLength(0);
    const f = await fixture();
    const challenge = await f.store.issue(binding());
    const filename = path.join(f.directory, (await f.files())[0]);
    const envelope = JSON.parse(await fs.readFile(filename, 'utf8')) as { record: { targetDigest: string } };
    envelope.record.targetDigest = hmac('forged-target');
    await fs.writeFile(filename, JSON.stringify(envelope));
    await expect(f.fresh().verify({ challengeId: challenge.challengeId, identity: binding() }, async () => true))
      .rejects.toMatchObject({ code: 'INVALID' });
  });

  it('lets exactly one concurrent consume win, and leaves a failed business mutation spent', async () => {
    const f = await fixture();
    const bound = binding();
    const challenge = await f.store.issue(bound);
    const permit = await f.store.verify({ challengeId: challenge.challengeId, identity: bound }, async () => true);
    const outcomes = await Promise.allSettled([
      f.store.consume({ challengeId: challenge.challengeId, permitId: permit.permitId, binding: bound }),
      f.fresh().consume({ challengeId: challenge.challengeId, permitId: permit.permitId, binding: bound }),
    ]);
    expect(outcomes.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(outcomes.filter((result) => result.status === 'rejected')).toHaveLength(1);
    // No business callback belongs to the store: a downstream failure never
    // rolls the already-durable permission back to verified.
    await expect(f.store.consume({ challengeId: challenge.challengeId, permitId: permit.permitId, binding: bound }))
      .rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('does not expose a renamed verified permit before directory durability can be acknowledged', async () => {
    const f = await fixture();
    const bound = binding();
    const challenge = await f.store.issue(bound);
    const nativeOpen = fs.open.bind(fs);
    let blockSync = true;
    vi.spyOn(fs, 'open').mockImplementation(async (filename, flags, mode) => {
      const handle = await nativeOpen(filename, flags, mode);
      if (String(filename) === f.directory && flags === 'r') {
        const nativeSync = handle.sync.bind(handle);
        vi.spyOn(handle, 'sync').mockImplementation(async () => {
          const raw = await fs.readFile(path.join(f.directory, (await f.files())[0]), 'utf8');
          if (blockSync && JSON.parse(raw).record.state === 'verified') throw new Error('directory fsync unavailable');
          await nativeSync();
        });
      }
      return handle;
    });
    await expect(f.store.verify({ challengeId: challenge.challengeId, identity: bound }, async () => true))
      .rejects.toMatchObject({ code: 'UNAVAILABLE' });
    await expect(f.fresh().consume({ challengeId: challenge.challengeId, permitId: 'A'.repeat(43), binding: bound }))
      .rejects.toMatchObject({ code: 'UNAVAILABLE' });
    blockSync = false;
    await expect(f.fresh().consume({ challengeId: challenge.challengeId, permitId: 'A'.repeat(43), binding: bound }))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    await expect(f.fresh().verify({ challengeId: challenge.challengeId, identity: bound }, async () => true))
      .rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('does not run a business mutation or resurrect a permit after consumed publication fails', async () => {
    const f = await fixture();
    const bound = binding();
    const challenge = await f.store.issue(bound);
    const permit = await f.store.verify({ challengeId: challenge.challengeId, identity: bound }, async () => true);
    const nativeOpen = fs.open.bind(fs);
    let blockSync = true;
    vi.spyOn(fs, 'open').mockImplementation(async (filename, flags, mode) => {
      const handle = await nativeOpen(filename, flags, mode);
      if (String(filename) === f.directory && flags === 'r') {
        const nativeSync = handle.sync.bind(handle);
        vi.spyOn(handle, 'sync').mockImplementation(async () => {
          const raw = await fs.readFile(path.join(f.directory, (await f.files())[0]), 'utf8');
          if (blockSync && JSON.parse(raw).record.state === 'consumed') throw new Error('directory fsync unavailable');
          await nativeSync();
        });
      }
      return handle;
    });
    const businessMutation = vi.fn(async () => undefined);
    await expect((async () => {
      await f.store.consume({ challengeId: challenge.challengeId, permitId: permit.permitId, binding: bound });
      await businessMutation();
    })()).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(businessMutation).not.toHaveBeenCalled();
    blockSync = false;
    await expect(f.fresh().consume({ challengeId: challenge.challengeId, permitId: permit.permitId, binding: bound }))
      .rejects.toMatchObject({ code: 'CONFLICT' });
  });
});
