








import { randomBytes, createHash } from 'crypto';
import type { BackupCodeSet, EncryptedBackupCode } from '../../types/auth.js';

export interface BackupCodesConfig {
  
  count: number;
  
  format: RegExp;
}

export const DEFAULT_BACKUP_CODES_CONFIG: BackupCodesConfig = {
  count: 10,
  format: /^[A-Z0-9]{4}-[A-Z0-9]{4}$/,
};







export function generateBackupCodes(count: number = 10): string[] {
  const codes: string[] = [];

  for (let i = 0; i < count; i++) {
    const part1 = randomBytes(2).toString('hex').toUpperCase();
    const part2 = randomBytes(2).toString('hex').toUpperCase();
    codes.push(`${part1}-${part2}`);
  }

  return codes;
}







export function hashBackupCode(code: string): string {
  const normalized = code.toUpperCase().replace(/[^A-Z0-9]/g, '');
  return createHash('sha256').update(normalized).digest('hex');
}








export function createBackupCodeSet(userId: string, codes: string[]): BackupCodeSet {
  const hashedCodes: EncryptedBackupCode[] = codes.map(code => ({
    id: randomBytes(16).toString('hex'),
    hash: hashBackupCode(code),
    used: false,
  }));

  return {
    userId,
    codes: hashedCodes,
    generatedAt: new Date().toISOString(),
  };
}








export function verifyBackupCode(
  codeSet: BackupCodeSet,
  code: string
): { valid: boolean; codeSet: BackupCodeSet; codesRemaining: number } {
  const hashedCode = hashBackupCode(code);

  
  const matchingCodeIndex = codeSet.codes.findIndex(
    c => c.hash === hashedCode && !c.used
  );

  if (matchingCodeIndex === -1) {
    return {
      valid: false,
      codeSet,
      codesRemaining: codeSet.codes.filter(c => !c.used).length,
    };
  }

  
  const updatedCodes = [...codeSet.codes];
  updatedCodes[matchingCodeIndex] = {
    ...updatedCodes[matchingCodeIndex],
    used: true,
    usedAt: new Date().toISOString(),
  };

  const updatedCodeSet: BackupCodeSet = {
    ...codeSet,
    codes: updatedCodes,
    lastUsedAt: new Date().toISOString(),
  };

  return {
    valid: true,
    codeSet: updatedCodeSet,
    codesRemaining: updatedCodes.filter(c => !c.used).length,
  };
}







export function getRemainingCodesCount(codeSet: BackupCodeSet | null): number {
  if (!codeSet) return 0;
  return codeSet.codes.filter(c => !c.used).length;
}







export function hasUnusedCodes(codeSet: BackupCodeSet | null): boolean {
  return getRemainingCodesCount(codeSet) > 0;
}








export function isValidCodeFormat(
  code: string,
  format: RegExp = DEFAULT_BACKUP_CODES_CONFIG.format
): boolean {
  const normalized = code.toUpperCase().replace(/[^A-Z0-9-]/g, '');
  return format.test(normalized);
}







export function formatCodesForDisplay(codes: string[]): string[] {
  return codes.map((code, index) => {
    const num = (index + 1).toString().padStart(2, '0');
    return `${num}. ${code}`;
  });
}








export function shouldRegenerateCodes(
  codeSet: BackupCodeSet | null,
  threshold: number = 2
): boolean {
  return getRemainingCodesCount(codeSet) <= threshold;
}
