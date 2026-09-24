import { createHash } from 'node:crypto';
import type { BackupCodeSet, EncryptedTOTPSecret } from '../types/auth.js';

/** Closed material digests, not authentication proofs. Never hash plaintext codes. */
function record(value: unknown, required: string[], optional: string[] = []): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      required.some(key => !Object.hasOwn(value, key)) ||
      Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) {
    throw new Error('Invalid retirement material');
  }
}
function text(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !value || value.length > 16384 || value.includes('\0')) throw new Error('Invalid retirement material');
}
function timestamp(value: unknown): void {
  text(value);
  if (!Number.isFinite(Date.parse(value))) throw new Error('Invalid retirement material');
}
function encoded(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean' ||
      (typeof value === 'number' && Number.isFinite(value))) return JSON.stringify(value);
  if (typeof value !== 'object') throw new Error('Invalid retirement material');
  if (Array.isArray(value)) return `[${value.map(encoded).join(',')}]`;
  const data = value as Record<string, unknown>;
  return `{${Object.keys(data).filter(key => data[key] !== undefined).sort()
    .map(key => `${JSON.stringify(key)}:${encoded(data[key])}`).join(',')}}`;
}
export function retirementMaterialDigest(domain: string, value: unknown): string {
  return createHash('sha256').update(`tinyland-auth:totp-retirement:${domain}:v1\0`).update(encoded(value)).digest('hex');
}
export function assertRetirementFactor(value: unknown): asserts value is EncryptedTOTPSecret {
  record(value, ['userId', 'handle', 'encryptedSecret', 'iv', 'authTag', 'salt', 'createdAt', 'backupCodesGenerated', 'version'],
    ['lastUsedAt', 'lastUsedTotpStep']);
  for (const key of ['userId', 'handle', 'encryptedSecret', 'iv', 'authTag', 'salt']) text(value[key]);
  timestamp(value.createdAt);
  if (value.version !== 1 || typeof value.backupCodesGenerated !== 'boolean') throw new Error('Invalid retirement material');
  if (value.lastUsedAt !== undefined) timestamp(value.lastUsedAt);
  if (value.lastUsedTotpStep !== undefined && (typeof value.lastUsedTotpStep !== 'number' ||
      !Number.isSafeInteger(value.lastUsedTotpStep) || value.lastUsedTotpStep < 0)) throw new Error('Invalid retirement material');
}
export function assertRetirementBackupCodes(value: unknown): asserts value is BackupCodeSet {
  record(value, ['userId', 'codes', 'generatedAt'], ['lastUsedAt']);
  text(value.userId); timestamp(value.generatedAt);
  if (value.lastUsedAt !== undefined) timestamp(value.lastUsedAt);
  if (!Array.isArray(value.codes) || value.codes.length > 256) throw new Error('Invalid retirement material');
  const ids = new Set<string>(); const hashes = new Set<string>();
  for (const code of value.codes) {
    record(code, ['id', 'hash', 'used'], ['usedAt']); text(code.id);
    if (typeof code.hash !== 'string' || !/^[a-f0-9]{64}$/.test(code.hash) || typeof code.used !== 'boolean' ||
        ids.has(code.id) || hashes.has(code.hash)) throw new Error('Invalid retirement material');
    if (code.usedAt !== undefined) timestamp(code.usedAt);
    ids.add(code.id); hashes.add(code.hash);
  }
}
export function totpRetirementFactorGeneration(factor: EncryptedTOTPSecret): string {
  assertRetirementFactor(factor);
  const { lastUsedAt: _lastUsedAt, lastUsedTotpStep: _lastUsedTotpStep, ...generation } = factor;
  return retirementMaterialDigest('factor-generation', generation);
}
export function totpRetirementFactorSnapshotDigest(factor: EncryptedTOTPSecret): string {
  assertRetirementFactor(factor);
  return retirementMaterialDigest('factor-snapshot', factor);
}
export function totpRetirementRecoverySetDigest(codes: BackupCodeSet | null): string | null {
  if (codes === null) return null;
  assertRetirementBackupCodes(codes);
  return retirementMaterialDigest('recovery-set', codes);
}
