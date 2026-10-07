import {
  generateSecret,
  generateSync,
  generateURI,
  verify,
  verifySync,
} from "otplib";

/**
 * otplib v13 compatibility shim.
 *
 * otplib v13 dropped the stateful `authenticator` singleton (with its
 * `checkDelta`/`verify`/`keyuri` methods) in favour of stateless functional
 * exports backed by `@otplib/core` / `@otplib/totp`. This module reimplements
 * the small surface the rest of the codebase depends on — a configurable step /
 * verification window, token generation, URI generation, boolean verification,
 * and (critically) the `checkDelta` primitive that the replay-guard relies on —
 * on top of those functional exports.
 *
 * Security floor: v13 enforces a 128-bit (16-byte) minimum secret length via
 * `SecretTooShortError`. We do NOT weaken that floor. Freshly generated secrets
 * are 160-bit (20 bytes). For already-issued sub-floor secrets we surface a
 * clear, actionable migration error instead of otplib's low-level message and
 * instead of silently padding (which would change the effective secret).
 */

/**
 * Minimum TOTP secret length in bytes (128 bits, RFC 4226 floor). This mirrors
 * `@otplib/core`'s `MIN_SECRET_BYTES` and must never be lowered.
 */
export const MIN_SECRET_BYTES = 16;

type AuthenticatorConfig = {
  step: number;
  window: number;
  digits: number;
};

// Module-level configuration replacing v12's mutable `authenticator.options`.
const config: AuthenticatorConfig = {
  step: 30,
  window: 1,
  digits: 6,
};

/**
 * Number of decoded secret bytes represented by a Base32 string. Padding and
 * whitespace are ignored; this is a floor estimate (5 bits per Base32 char).
 */
function base32ByteLength(secret: string): number {
  // Count significant characters with a linear scan: no backtracking regex on
  // caller-supplied input (CodeQL js/polynomial-redos).
  const compact = secret.replace(/\s/g, "");
  let end = compact.length;
  while (end > 0 && compact.charCodeAt(end - 1) === 61 /* "=" */) end--;
  return Math.floor((end * 5) / 8);
}

/**
 * Enforce the 128-bit security floor with a clear, actionable error. Called on
 * the crypto paths (generate/verify/checkDelta) so a legacy sub-floor secret
 * fails closed and visibly rather than throwing otplib's internal error or —
 * worse — being silently padded.
 */
function assertSecretMeetsFloor(secret: string): void {
  if (base32ByteLength(secret) < MIN_SECRET_BYTES) {
    throw new Error(
      `TOTP secret is below the ${MIN_SECRET_BYTES}-byte (128-bit) security ` +
        `floor and can no longer be used; re-enroll this credential with a ` +
        `freshly generated secret.`,
    );
  }
}

/**
 * Symmetric verification tolerance in seconds derived from the configured
 * step/window (window=1 step=30 -> +/-30s -> +/-1 time-step), matching the v12
 * `window` semantics the callers configured.
 */
function epochTolerance(): number {
  return config.window * config.step;
}

export function configureAuthenticator(options: {
  step?: number;
  window?: number;
  digits?: number;
}): void {
  if (options.step !== undefined) config.step = options.step;
  if (options.window !== undefined) config.window = options.window;
  if (options.digits !== undefined) config.digits = options.digits;
}

export function generateAuthenticatorSecret(): string {
  // 20 bytes / 160 bits — comfortably above the 128-bit floor. Never weaken.
  return generateSecret({ length: 20 });
}

export function generateAuthenticatorUri(
  label: string,
  issuer: string,
  secret: string,
): string {
  return generateURI({
    strategy: "totp",
    issuer,
    label,
    secret,
    digits: config.digits as 6,
    period: config.step,
  });
}

/**
 * Optional epoch (seconds) override. Omitted in production so otplib reads the
 * system clock itself; supplied only when the test harness installed a clock seam.
 */
function epochOption(epochSeconds?: number): { epoch?: number } {
  return epochSeconds === undefined ? {} : { epoch: epochSeconds };
}

export function generateAuthenticatorToken(
  secret: string,
  epochSeconds?: number,
): string {
  assertSecretMeetsFloor(secret);
  return generateSync({
    strategy: "totp",
    secret,
    digits: config.digits as 6,
    period: config.step,
    ...epochOption(epochSeconds),
  });
}

export async function verifyAuthenticatorToken(
  secret: string,
  token: string,
  epochSeconds?: number,
): Promise<boolean> {
  assertSecretMeetsFloor(secret);
  const result = await verify({
    strategy: "totp",
    secret,
    token,
    digits: config.digits as 6,
    period: config.step,
    epochTolerance: epochTolerance(),
    ...epochOption(epochSeconds),
  });
  return result.valid;
}

export function getAuthenticatorStep(): number {
  return config.step;
}

/**
 * Returns how many time-steps away from the current step the token matched,
 * within the configured verification window (e.g. -1, 0, +1 for window=1), or
 * `null` when the token is invalid. This is the primitive that lets callers
 * derive the absolute time-step a code was minted for and enforce single-use
 * (replay) protection: absoluteStep = currentStep + delta.
 *
 * otplib v13's `verifySync` returns `{ valid, delta, timeStep, epoch }` on
 * success, so we recover the exact delta directly (no lossy fallback needed).
 */
export function getAuthenticatorCheckDelta(
  secret: string,
  token: string,
  epochSeconds?: number,
): number | null {
  assertSecretMeetsFloor(secret);
  const result = verifySync({
    strategy: "totp",
    secret,
    token,
    digits: config.digits as 6,
    period: config.step,
    epochTolerance: epochTolerance(),
    ...epochOption(epochSeconds),
  });
  return result.valid ? result.delta : null;
}
