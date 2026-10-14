import * as qrcode from "qrcode";
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "crypto";
import type {
  TOTPSecret,
  EncryptedData,
  TOTPConfig,
} from "../../types/index.js";
import { timingSafeVerify } from "../security/index.js";
import { epochSecondsFor, nowMsFor } from "../seams/index.js";
import {
  configureAuthenticator,
  generateAuthenticatorToken,
  generateAuthenticatorSecret,
  generateAuthenticatorUri,
  verifyAuthenticatorToken,
  getAuthenticatorCheckDelta,
  getAuthenticatorStep,
} from "../../totp/otplib-compat.js";

configureAuthenticator({ window: 1 });

const ALGORITHM = "aes-256-gcm";
const SALT_LENGTH = 32;
const IV_LENGTH = 16;
const KEY_LENGTH = 32;

// Constant-time dummy secret for the unknown-user path. Must satisfy otplib
// v13's 128-bit (16-byte) minimum secret length, otherwise verification of the
// dummy throws SecretTooShortError instead of running the constant-time work.
// 32 Base32 chars = 160 bits = 20 bytes.
const DUMMY_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

/**
 * Instances built by this module's own constructor (RS6). Module-private: no
 * caller can add an object to it, so a structural look-alike is never genuine.
 */
const genuineServices = new WeakSet<object>();

/**
 * The absolute TOTP time-step for the current wall-clock time. A token minted
 * for time-step N is `Math.floor(now / period)`; comparing consumed steps
 * across verifications gives us a monotonic single-use marker. A module
 * function, not a method, so no subclass or instance patch can move it.
 */
function currentStepFor(service: object): number {
  const stepSeconds = getAuthenticatorStep();
  return Math.floor(nowMsFor(service) / 1000 / stepSeconds);
}

export interface TOTPServiceConfig {
  encryptionKey: string;

  issuer: string;
}

/**
 * TOTP enrolment and verification.
 *
 * 1.0.0 (RS6): there is no code-accepting shortcut and no injectable verifier.
 * Every token is checked by otplib (RFC 6238) against the stored secret. Time
 * comes from the system clock; a test clock can be attached only through the
 * gated `./testing` build, never through this config.
 */
export class TOTPService {
  private encryptionKey: string;
  private issuer: string;

  constructor(config: TOTPServiceConfig) {
    this.encryptionKey = config.encryptionKey;
    this.issuer = config.issuer;
    genuineServices.add(this);
  }

  async generateSecret(handle: string, email?: string): Promise<TOTPSecret> {
    const secret = generateAuthenticatorSecret();
    const accountLabel = email || handle;
    const otpauth = generateAuthenticatorUri(accountLabel, this.issuer, secret);
    const qrCodeUrl = await qrcode.toDataURL(otpauth);

    return {
      handle,
      email,
      secret,
      qrCodeUrl,
      createdAt: new Date(nowMsFor(this)),
    };
  }

  encrypt(text: string): EncryptedData {
    const salt = randomBytes(SALT_LENGTH);
    const key = scryptSync(this.encryptionKey, salt, KEY_LENGTH);
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, key, iv);

    const encrypted = Buffer.concat([
      cipher.update(text, "utf8"),
      cipher.final(),
    ]);

    const tag = cipher.getAuthTag();

    return {
      encrypted: encrypted.toString("base64"),
      salt: salt.toString("base64"),
      iv: iv.toString("base64"),
      tag: tag.toString("base64"),
    };
  }

  decrypt(encryptedData: EncryptedData): string {
    const salt = Buffer.from(encryptedData.salt, "base64");
    const key = scryptSync(this.encryptionKey, salt, KEY_LENGTH);
    const iv = Buffer.from(encryptedData.iv, "base64");
    const tag = Buffer.from(encryptedData.tag, "base64");
    const encrypted = Buffer.from(encryptedData.encrypted, "base64");

    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);

    return decrypted.toString("utf8");
  }

  async verifyToken(
    secretOrNull: TOTPSecret | null,
    token: string,
  ): Promise<boolean> {
    const cleanToken = token.replace(/\s/g, "");
    const epochSeconds = epochSecondsFor(this);

    return await timingSafeVerify(async () => {
      if (!secretOrNull) {
        await verifyAuthenticatorToken(DUMMY_SECRET, cleanToken, epochSeconds);
        return false;
      }

      return await verifyAuthenticatorToken(
        secretOrNull.secret,
        cleanToken,
        epochSeconds,
      );
    }, 150);
  }

  /**
   * Replay-resistant token verification.
   *
   * Unlike {@link verifyToken}, this enforces single-use of a code across the
   * accepted `+/-window` skew: it derives the absolute time-step the supplied
   * code was minted for and rejects any step that is `<=` the caller-supplied
   * `lastUsedStep` (the previously-consumed step for this user). On success it
   * returns the consumed step so the caller can persist it and reject replays
   * of the same code — even while that code is still inside its validity window.
   *
   * @param secretOrNull the user's TOTP secret (or `null` for constant-time
   *   handling of unknown users)
   * @param token the submitted code
   * @param lastUsedStep the last time-step this user successfully consumed, if
   *   any; omit for the first verification
   * @returns `{ valid, step }` — `valid` is false for bad codes AND for replays;
   *   `step` (present only when valid) is the newly-consumed step to persist
   */
  async verifyTokenWithStep(
    secretOrNull: TOTPSecret | null,
    token: string,
    lastUsedStep?: number,
  ): Promise<{ valid: boolean; step?: number }> {
    const cleanToken = token.replace(/\s/g, "");
    const epochSeconds = epochSecondsFor(this);

    let matchedStep: number | undefined;

    const valid = await timingSafeVerify(async () => {
      if (!secretOrNull) {
        // Constant-time dummy path for unknown users.
        getAuthenticatorCheckDelta(DUMMY_SECRET, cleanToken, epochSeconds);
        return false;
      }

      const delta = getAuthenticatorCheckDelta(
        secretOrNull.secret,
        cleanToken,
        epochSeconds,
      );
      if (delta === null) {
        return false;
      }

      const step = currentStepFor(this) + delta;
      if (lastUsedStep !== undefined && step <= lastUsedStep) {
        // Code is cryptographically valid but was already consumed (or is
        // older than the last consumed step): reject as a replay.
        return false;
      }

      matchedStep = step;
      return true;
    }, 150);

    return valid ? { valid: true, step: matchedStep } : { valid: false };
  }

  generateToken(secret: TOTPSecret): string {
    return generateAuthenticatorToken(secret.secret, epochSecondsFor(this));
  }

  async generateQRCode(secret: TOTPSecret): Promise<string> {
    const otpauth = generateAuthenticatorUri(
      secret.email || secret.handle,
      this.issuer,
      secret.secret,
    );
    return await qrcode.toDataURL(otpauth);
  }

  encryptBackupCodes(codes: string[]): EncryptedData {
    return this.encrypt(JSON.stringify(codes));
  }

  decryptBackupCodes(encryptedData: EncryptedData): string[] {
    const json = this.decrypt(encryptedData);
    return JSON.parse(json);
  }
}

/**
 * `Reflect.apply`, captured at module evaluation (RS6, W8 r2). The captured
 * methods run through it, never through `method.call(...)`: `.call` is looked
 * up on the function object at every invocation, so an own `call`, a new
 * [[Prototype]] on a captured method, or a later patch of
 * `Function.prototype.call` would otherwise decide what runs.
 */
const invoke = Reflect.apply;

/**
 * The methods an authority coordinator may call, captured from the class at
 * module evaluation, before any importer runs. A later patch of
 * `TOTPService.prototype` or of an instance is never called through them.
 * The captured function objects stay reachable as
 * `TOTPService.prototype.<method>`, so each one is frozen here as well:
 * defining a property on one or changing its [[Prototype]] throws.
 */
const intrinsic = Object.freeze({
  generateSecret: TOTPService.prototype.generateSecret,
  generateQRCode: TOTPService.prototype.generateQRCode,
  encrypt: TOTPService.prototype.encrypt,
  decrypt: TOTPService.prototype.decrypt,
  verifyTokenWithStep: TOTPService.prototype.verifyTokenWithStep,
});
for (const method of Object.values(intrinsic)) Object.freeze(method);

/** The TOTP primitives a durable authority coordinator runs, bound to one genuine service. */
export interface TrustedTOTPPrimitives {
  generateSecret(handle: string, email?: string): Promise<TOTPSecret>;
  generateQRCode(secret: TOTPSecret): Promise<string>;
  encrypt(text: string): EncryptedData;
  decrypt(encryptedData: EncryptedData): string;
  verifyTokenWithStep(
    secretOrNull: TOTPSecret | null,
    token: string,
    lastUsedStep?: number,
  ): Promise<{ valid: boolean; step?: number }>;
}

/**
 * RS6 (internal, not re-exported from any package entry): accept only a
 * TOTPService made by this module's constructor, with no subclass and no
 * instance override of an authority method, and bind the captured class
 * methods to it. The returned primitives never call a caller-supplied method,
 * so no configuration can make a code verify, pin the enrolment secret or
 * substitute the journal cipher. Throws a TypeError otherwise.
 */
export function bindTrustedTOTPService(value: unknown): TrustedTOTPPrimitives {
  if (
    typeof value !== "object" ||
    value === null ||
    !genuineServices.has(value) ||
    Object.getPrototypeOf(value) !== TOTPService.prototype
  ) {
    throw new TypeError(
      "Authority coordinators require a TOTPService from createTOTPService(); custom or wrapped TOTP implementations are refused (RS6)",
    );
  }
  for (const name of Object.keys(intrinsic)) {
    if (Object.prototype.hasOwnProperty.call(value, name)) {
      throw new TypeError(
        `Authority coordinators refuse a TOTPService whose ${name} is overridden (RS6)`,
      );
    }
  }
  const service = value as TOTPService;
  return Object.freeze({
    generateSecret: (handle: string, email?: string): Promise<TOTPSecret> =>
      invoke(intrinsic.generateSecret, service, [handle, email]),
    generateQRCode: (secret: TOTPSecret): Promise<string> =>
      invoke(intrinsic.generateQRCode, service, [secret]),
    encrypt: (text: string): EncryptedData =>
      invoke(intrinsic.encrypt, service, [text]),
    decrypt: (encryptedData: EncryptedData): string =>
      invoke(intrinsic.decrypt, service, [encryptedData]),
    verifyTokenWithStep: (
      secretOrNull: TOTPSecret | null,
      token: string,
      lastUsedStep?: number,
    ): Promise<{ valid: boolean; step?: number }> =>
      invoke(intrinsic.verifyTokenWithStep, service, [secretOrNull, token, lastUsedStep]),
  });
}

export function createTOTPService(config: TOTPConfig): TOTPService {
  return new TOTPService({
    encryptionKey: config.encryptionKey,
    issuer: config.issuer,
  });
}
