








import * as bcrypt from 'bcryptjs';
import { randomInt } from 'crypto';




export interface PasswordHashConfig {
  
  rounds: number;
}

const DEFAULT_CONFIG: PasswordHashConfig = {
  rounds: 12,
};














export async function hashPassword(
  password: string,
  config: Partial<PasswordHashConfig> = {}
): Promise<string> {
  const { rounds } = { ...DEFAULT_CONFIG, ...config };

  if (rounds < 4 || rounds > 31) {
    throw new Error('bcrypt rounds must be between 4 and 31');
  }

  return bcrypt.hash(password, rounds);
}


















export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  
  return bcrypt.compare(password, hash);
}


















export function needsRehash(hash: string, desiredRounds: number): boolean {
  
  const match = hash.match(/^\$2[aby]?\$(\d+)\$/);
  if (!match) {
    return true; 
  }

  const currentRounds = parseInt(match[1], 10);
  return currentRounds < desiredRounds;
}







export function getHashRounds(hash: string): number | null {
  const match = hash.match(/^\$2[aby]?\$(\d+)\$/);
  return match ? parseInt(match[1], 10) : null;
}










export function generateSecurePassword(
  length: number = 16,
  options: {
    includeUppercase?: boolean;
    includeLowercase?: boolean;
    includeNumbers?: boolean;
    includeSpecial?: boolean;
  } = {}
): string {
  const {
    includeUppercase = true,
    includeLowercase = true,
    includeNumbers = true,
    includeSpecial = true,
  } = options;

  let charset = '';
  if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (includeNumbers) charset += '0123456789';
  if (includeSpecial) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

  if (charset.length === 0) {
    charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
  }

  let password = '';

  for (let i = 0; i < length; i++) {
    password += charset[randomInt(charset.length)];
  }

  return password;
}
