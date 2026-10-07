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
import type { Clock } from "../clock/index.js";
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
 * TOTP verification seam. The default implementation is otplib (RFC 6238) and
 * is what every production caller gets. `epochSeconds` is `undefined` unless
 * the service was constructed with a `Clock`, in which case it carries that
 * clock's time so verification and the replay step agree on "now".
 */
export interface TotpVerifier {
  verify(secret: string, token: string, epochSeconds?: number): Promise<boolean>;
  checkDelta(
    secret: string,
    token: string,
    epochSeconds?: number,
  ): number | null;
}

export const otplibTotpVerifier: TotpVerifier = {
  verify: (secret, token, epochSeconds) =>
    verifyAuthenticatorToken(secret, token, epochSeconds),
  checkDelta: (secret, token, epochSeconds) =>
    getAuthenticatorCheckDelta(secret, token, epochSeconds),
};

export interface TOTPServiceConfig {
  encryptionKey: string;

  issuer: string;

  devMode?: boolean;

  testCode?: string;

  /** Time source. Defaults to the system clock. */
  clock?: Clock;

  /** Verification implementation. Defaults to {@link otplibTotpVerifier}. */
  verifier?: TotpVerifier;
}

export class TOTPService {
  private encryptionKey: string;
  private issuer: string;
  private devMode: boolean;
  private testCode?: string;
  private clock?: Clock;
  private verifier: TotpVerifier;

  constructor(config: TOTPServiceConfig) {
    this.encryptionKey = config.encryptionKey;
    this.issuer = config.issuer;
    this.devMode = config.devMode || false;
    this.testCode = config.testCode;
    this.clock = config.clock;
    this.verifier = config.verifier ?? otplibTotpVerifier;
  }

  /** Milliseconds since the epoch from the injected clock, else the system. */
  private nowMs(): number {
    return this.clock ? this.clock.now() : Date.now();
  }

  /**
   * Epoch seconds to hand to the verifier. `undefined` without an injected
   * clock, so the default path lets otplib read system time as it always has.
   */
  private epochSeconds(): number | undefined {
    return this.clock ? Math.floor(this.clock.now() / 1000) : undefined;
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
      createdAt: new Date(this.nowMs()),
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

    if (this.devMode && this.testCode && cleanToken === this.testCode) {
      return true;
    }

    return await timingSafeVerify(async () => {
      if (!secretOrNull) {
        await this.verifier.verify(
          DUMMY_SECRET,
          cleanToken,
          this.epochSeconds(),
        );
        return false;
      }

      return await this.verifier.verify(
        secretOrNull.secret,
        cleanToken,
        this.epochSeconds(),
      );
    }, 150);
  }

  /**
   * The absolute TOTP time-step for the current wall-clock time. A token minted
   * for time-step N is `Math.floor(now / period)`; comparing consumed steps
   * across verifications gives us a monotonic single-use marker.
   */
  private currentStep(): number {
    const stepSeconds = getAuthenticatorStep();
    return Math.floor(this.nowMs() / 1000 / stepSeconds);
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

    if (this.devMode && this.testCode && cleanToken === this.testCode) {
      const step = this.currentStep();
      if (lastUsedStep !== undefined && step <= lastUsedStep) {
        return { valid: false };
      }
      return { valid: true, step };
    }

    let matchedStep: number | undefined;

    const valid = await timingSafeVerify(async () => {
      if (!secretOrNull) {
        // Constant-time dummy path for unknown users.
        this.verifier.checkDelta(DUMMY_SECRET, cleanToken, this.epochSeconds());
        return false;
      }

      const delta = this.verifier.checkDelta(
        secretOrNull.secret,
        cleanToken,
        this.epochSeconds(),
      );
      if (delta === null) {
        return false;
      }

      const step = this.currentStep() + delta;
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
    return generateAuthenticatorToken(secret.secret, this.epochSeconds());
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

export function createTOTPService(config: TOTPConfig): TOTPService {
  return new TOTPService({
    encryptionKey: config.encryptionKey,
    issuer: config.issuer,
    devMode: config.devMode,
  });
}
