/**
 * Internal test-seam registry (RS5/RS6).
 *
 * This module is NOT exported from any package entry point. Production code
 * only reads it: with nothing installed, every service uses the system clock
 * and the CSPRNG recovery-code generator, and there is no public option that
 * changes either. The only writer is the `./testing` build (`src/testing`),
 * which is compiled outside the production build, is absent from the
 * published artifact, and refuses to load unless `NODE_ENV` is exactly
 * `"test"`.
 *
 * A production bundle that imports the package entry points keeps the empty
 * registry and the readers only; the writer below is unused there and is
 * tree-shaken out (`scripts/check-production-artifact.mjs` asserts it).
 */

/** Time source: milliseconds since the Unix epoch. */
export interface Clock {
  now(): number;
}

/** Recovery-code generator: returns `count` codes in the `XXXX-XXXX` format. */
export type BackupCodeGenerator = (count: number) => string[];

export interface ServiceSeams {
  readonly clock?: Clock;
  readonly generateBackupCodes?: BackupCodeGenerator;
}

const registry = new WeakMap<object, ServiceSeams>();

/** Seams installed on `service`, if any. Production services have none. */
export function seamsOf(service: object): ServiceSeams | undefined {
  return registry.get(service);
}

/** Wall-clock milliseconds for `service`: its installed clock, else the system. */
export function nowMsFor(service: object): number {
  const clock = registry.get(service)?.clock;
  return clock ? clock.now() : Date.now();
}

/**
 * Epoch seconds to pass to otplib for `service`. `undefined` when no clock is
 * installed, so the production path lets otplib read system time itself.
 */
export function epochSecondsFor(service: object): number | undefined {
  const clock = registry.get(service)?.clock;
  return clock ? Math.floor(clock.now() / 1000) : undefined;
}

/**
 * Attach seams to one service instance. Called only from `src/testing`.
 * Installing twice on the same instance is refused so a harness cannot
 * silently swap a clock mid-run.
 */
export function installSeams(service: object, seams: ServiceSeams): void {
  if (registry.has(service)) {
    throw new Error('Test seams are already installed on this service');
  }
  registry.set(service, Object.freeze({ ...seams }));
}
