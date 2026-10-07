/**
 * Time source seam.
 *
 * Services that compare against wall-clock time accept an optional `Clock`.
 * When none is supplied they keep using `Date.now()` / `new Date()` exactly as
 * before, so production behaviour is unchanged. A harness supplies a manual
 * clock (see the `./testing` subpath) to drive expiry and TOTP time-steps
 * deterministically.
 */
export interface Clock {
  /** Milliseconds since the Unix epoch. */
  now(): number;
}

export const systemClock: Clock = {
  now: () => Date.now(),
};
