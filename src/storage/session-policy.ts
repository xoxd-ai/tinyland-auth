import type { Session } from '../types/auth.js';
import type { BoundedSessionPolicy } from '../types/config.js';

export function assertBoundedSessionPolicy(policy: BoundedSessionPolicy): void {
  if (!policy || !Number.isSafeInteger(policy.maxConcurrentSessions) ||
      policy.maxConcurrentSessions < 1 || policy.overflow !== 'evict-oldest-created') {
    throw new Error('Invalid bounded session policy');
  }
}

/** Validate identity and ordering fields before modifying an existing session store. */
export function assertStoredSessions(value: unknown): asserts value is Session[] {
  if (!Array.isArray(value)) throw new Error('Invalid session store');
  const ids = new Set<string>();
  for (const session of value) {
    if (!session || typeof session !== 'object' || Array.isArray(session) ||
        typeof session.id !== 'string' || !session.id || session.id.includes('\0') ||
        typeof session.userId !== 'string' || !session.userId || session.userId.includes('\0') ||
        typeof session.createdAt !== 'string' || !Number.isFinite(Date.parse(session.createdAt)) ||
        typeof session.expires !== 'string' || !Number.isFinite(Date.parse(session.expires)) ||
        ids.has(session.id)) throw new Error('Invalid session store');
    ids.add(session.id);
  }
}

/** Keep the new session and newest existing sessions; device metadata is never authority. */
export function boundedSessions(
  sessions: Session[], session: Session, policy: BoundedSessionPolicy, now: number,
): Session[] {
  assertBoundedSessionPolicy(policy);
  assertStoredSessions([...sessions, session]);
  const own = sessions.filter((item) => item.userId === session.userId && Date.parse(item.expires) > now);
  own.sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt) ||
    (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const retained = own.slice(Math.max(0, own.length - (policy.maxConcurrentSessions - 1)));
  return [...sessions.filter((item) => item.userId !== session.userId), ...retained, session];
}
