






import { describe, it, expect } from 'vitest';
import { TOTPService, createTOTPService } from '../src/core/totp/index.js';
import { DEFAULT_AUTH_CONFIG } from '../src/types/config.js';
import type { TOTPSecret, EncryptedData } from '../src/types/auth.js';


const TEST_ENCRYPTION_KEY = 'abcdefghijklmnopqrstuvwxyz123456';

function createTestService(overrides: Partial<ConstructorParameters<typeof TOTPService>[0]> = {}): TOTPService {
  return new TOTPService({
    encryptionKey: TEST_ENCRYPTION_KEY,
    issuer: 'Test App',
    ...overrides,
  });
}

describe('TOTPService', () => {
  describe('generateSecret', () => {
    it('should generate a TOTP secret with required fields', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');

      expect(secret.handle).toBe('testuser');
      expect(secret.email).toBe('test@example.com');
      expect(secret.secret).toBeTruthy();
      expect(secret.qrCodeUrl).toBeTruthy();
      expect(secret.createdAt).toBeInstanceOf(Date);
    });

    it('should generate a base32 secret string', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');

      
      expect(secret.secret).toMatch(/^[A-Z2-7]+$/);
    });

    it('should generate unique secrets for different users', async () => {
      const service = createTestService();
      const secret1 = await service.generateSecret('user1', 'user1@example.com');
      const secret2 = await service.generateSecret('user2', 'user2@example.com');

      expect(secret1.secret).not.toBe(secret2.secret);
    });

    it('should generate a QR code data URL', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');

      expect(secret.qrCodeUrl).toMatch(/^data:image\/png;base64,/);
    });

    it('should generate unique secrets on successive calls for same user', async () => {
      const service = createTestService();
      const secret1 = await service.generateSecret('testuser', 'test@example.com');
      const secret2 = await service.generateSecret('testuser', 'test@example.com');

      expect(secret1.secret).not.toBe(secret2.secret);
    });
  });

  describe('encrypt / decrypt', () => {
    it('should roundtrip encrypt and decrypt a string', () => {
      const service = createTestService();
      const plaintext = 'JBSWY3DPEHPK3PXP';

      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertexts for same plaintext (random IV/salt)', () => {
      const service = createTestService();
      const plaintext = 'test-secret';

      const encrypted1 = service.encrypt(plaintext);
      const encrypted2 = service.encrypt(plaintext);

      expect(encrypted1.encrypted).not.toBe(encrypted2.encrypted);
      expect(encrypted1.iv).not.toBe(encrypted2.iv);
      expect(encrypted1.salt).not.toBe(encrypted2.salt);
    });

    it('should return encrypted data with all required fields', () => {
      const service = createTestService();
      const encrypted = service.encrypt('test');

      expect(encrypted.encrypted).toBeTruthy();
      expect(encrypted.salt).toBeTruthy();
      expect(encrypted.iv).toBeTruthy();
      expect(encrypted.tag).toBeTruthy();
    });

    it('should fail to decrypt with wrong key', () => {
      const service1 = createTestService({ encryptionKey: 'abcdefghijklmnopqrstuvwxyz123456' });
      const service2 = createTestService({ encryptionKey: '654321zyxwvutsrqponmlkjihgfedcba' });

      const encrypted = service1.encrypt('secret');

      expect(() => service2.decrypt(encrypted)).toThrow();
    });

    it('should fail to decrypt tampered ciphertext', () => {
      const service = createTestService();
      const encrypted = service.encrypt('secret');

      
      const tampered: EncryptedData = {
        ...encrypted,
        encrypted: 'AAAA' + encrypted.encrypted.slice(4),
      };

      expect(() => service.decrypt(tampered)).toThrow();
    });

    it('should handle empty string encryption', () => {
      const service = createTestService();
      const encrypted = service.encrypt('');
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe('');
    });

    it('should handle unicode content', () => {
      const service = createTestService();
      const plaintext = 'Unicode test: \u00e9\u00e8\u00ea\u00eb \u4e16\u754c';

      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });
  });

  describe('verifyToken', () => {
    it('should verify a valid TOTP token', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');

      
      const token = service.generateToken(secret);

      const result = await service.verifyToken(secret, token);
      expect(result).toBe(true);
    });

    it('should reject an invalid TOTP token', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');

      const result = await service.verifyToken(secret, '000000');
      expect(result).toBe(false);
    });

    it('should handle null secret gracefully (returns false)', async () => {
      const service = createTestService();

      const result = await service.verifyToken(null, '123456');
      expect(result).toBe(false);
    });

    it('should strip whitespace from tokens', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');
      const token = service.generateToken(secret);

      
      const spacedToken = `${token.slice(0, 3)} ${token.slice(3)}`;
      const result = await service.verifyToken(secret, spacedToken);
      expect(result).toBe(true);
    });

    it('has no fixed-code bypass: legacy devMode/testCode options are ignored (RS6)', async () => {
      const service = new TOTPService({
        encryptionKey: TEST_ENCRYPTION_KEY,
        issuer: 'Test App',
        // @ts-expect-error devMode and testCode were removed from TOTPServiceConfig in 1.0.0
        devMode: true,
        testCode: '999999',
      });
      const secret = await service.generateSecret('testuser', 'test@example.com');

      const fixed = service.generateToken(secret) === '999999' ? '999998' : '999999';
      expect(await service.verifyToken(secret, fixed)).toBe(false);
      expect(await service.verifyToken(null, fixed)).toBe(false);
      expect(await service.verifyTokenWithStep(secret, fixed)).toEqual({ valid: false });
      expect(Object.keys(service)).not.toContain('devMode');
      expect(Object.keys(service)).not.toContain('testCode');
    });

    it('createTOTPService ignores a legacy devMode key on the config', async () => {
      const service = createTOTPService({
        ...DEFAULT_AUTH_CONFIG.totp,
        encryptionKey: TEST_ENCRYPTION_KEY,
        devMode: true,
      } as typeof DEFAULT_AUTH_CONFIG.totp);
      const secret = await service.generateSecret('testuser');
      expect(await service.verifyToken(secret, '999999')).toBe(service.generateToken(secret) === '999999');
      expect('devMode' in DEFAULT_AUTH_CONFIG.totp).toBe(false);
    });
  });

  describe('verifyTokenWithStep (replay protection)', () => {
    it('accepts a fresh code and returns the consumed step', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');
      const token = service.generateToken(secret);

      const result = await service.verifyTokenWithStep(secret, token);

      expect(result.valid).toBe(true);
      expect(typeof result.step).toBe('number');
    });

    it('REGRESSION: rejects the same code on second use (replay) when the prior step is fed back', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');
      const token = service.generateToken(secret);

      // First use: valid, yields the consumed step.
      const first = await service.verifyTokenWithStep(secret, token);
      expect(first.valid).toBe(true);
      const consumedStep = first.step!;

      // Second use of the SAME code, now that the step is marked consumed:
      // must be rejected even though the code is still inside its window.
      const second = await service.verifyTokenWithStep(secret, token, consumedStep);
      expect(second.valid).toBe(false);
      expect(second.step).toBeUndefined();
    });

    it('rejects any code whose step is <= the last consumed step (monotonic)', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');
      const token = service.generateToken(secret);

      const { step } = await service.verifyTokenWithStep(secret, token);

      // A future last-used marker (step ahead of the current code) rejects it.
      const stale = await service.verifyTokenWithStep(secret, token, step! + 5);
      expect(stale.valid).toBe(false);
    });

    it('still accepts a code when the last consumed step is older', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');
      const token = service.generateToken(secret);

      const { step } = await service.verifyTokenWithStep(secret, token);
      // A strictly-older last-used step must not block a newer code.
      const result = await service.verifyTokenWithStep(secret, token, step! - 1);
      expect(result.valid).toBe(true);
      expect(result.step).toBe(step);
    });

    it('rejects an invalid code and returns no step', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');

      const result = await service.verifyTokenWithStep(secret, '000000', undefined);
      expect(result.valid).toBe(false);
      expect(result.step).toBeUndefined();
    });

    it('handles a null secret gracefully (returns invalid, no step)', async () => {
      const service = createTestService();

      const result = await service.verifyTokenWithStep(null, '123456');
      expect(result.valid).toBe(false);
      expect(result.step).toBeUndefined();
    });

    it('keeps legacy verifyToken behavior unchanged (no replay state)', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');
      const token = service.generateToken(secret);

      // The stateless helper still accepts a valid code repeatedly — replay
      // protection is opt-in via verifyTokenWithStep.
      expect(await service.verifyToken(secret, token)).toBe(true);
      expect(await service.verifyToken(secret, token)).toBe(true);
    });
  });

  describe('generateToken', () => {
    it('should generate a 6-digit numeric token', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');
      const token = service.generateToken(secret);

      expect(token).toMatch(/^\d{6}$/);
    });

    it('should generate consistent tokens for the same secret within the same time window', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');

      const token1 = service.generateToken(secret);
      const token2 = service.generateToken(secret);

      expect(token1).toBe(token2);
    });
  });

  describe('generateQRCode', () => {
    it('should generate a QR code data URL from a secret', async () => {
      const service = createTestService();
      const secret = await service.generateSecret('testuser', 'test@example.com');

      const qrCode = await service.generateQRCode(secret);
      expect(qrCode).toMatch(/^data:image\/png;base64,/);
    });
  });

  describe('encryptBackupCodes / decryptBackupCodes', () => {
    it('should roundtrip backup code encryption', () => {
      const service = createTestService();
      const codes = ['ABCD-1234', 'EFGH-5678', 'IJKL-9012'];

      const encrypted = service.encryptBackupCodes(codes);
      const decrypted = service.decryptBackupCodes(encrypted);

      expect(decrypted).toEqual(codes);
    });

    it('should encrypt codes as JSON', () => {
      const service = createTestService();
      const codes = ['CODE-0001'];

      const encrypted = service.encryptBackupCodes(codes);

      
      expect(encrypted.encrypted).toBeTruthy();
      expect(encrypted.salt).toBeTruthy();
      expect(encrypted.iv).toBeTruthy();
      expect(encrypted.tag).toBeTruthy();
    });

    it('should handle empty code array', () => {
      const service = createTestService();
      const encrypted = service.encryptBackupCodes([]);
      const decrypted = service.decryptBackupCodes(encrypted);

      expect(decrypted).toEqual([]);
    });

    it('should produce different ciphertexts for same codes', () => {
      const service = createTestService();
      const codes = ['ABCD-1234'];

      const encrypted1 = service.encryptBackupCodes(codes);
      const encrypted2 = service.encryptBackupCodes(codes);

      expect(encrypted1.encrypted).not.toBe(encrypted2.encrypted);
    });
  });
});

describe('TOTP PBT: Generated secrets', () => {
  it('INVARIANT: generated secrets are always valid base32', async () => {
    const service = createTestService();
    const base32Regex = /^[A-Z2-7]+=*$/;

    
    for (let i = 0; i < 50; i++) {
      const secret = await service.generateSecret(`user${i}`, `user${i}@example.com`);
      expect(secret.secret).toMatch(base32Regex);
    }
  });

  it('INVARIANT: generated secrets have sufficient length for security', async () => {
    const service = createTestService();

    
    
    for (let i = 0; i < 50; i++) {
      const secret = await service.generateSecret(`user${i}`, `user${i}@example.com`);
      expect(secret.secret.length).toBeGreaterThanOrEqual(16);
    }
  });

  it('INVARIANT: encrypt/decrypt roundtrip preserves arbitrary strings', () => {
    const service = createTestService();

    
    const testStrings = [
      'JBSWY3DPEHPK3PXP',
      'a',
      'A'.repeat(100),
      'special chars: !@#$%^&*()',
      '\n\t\r',
      '\u0000null\u0000byte',
      '\ud83d\ude0a emoji test',
    ];

    for (const str of testStrings) {
      const encrypted = service.encrypt(str);
      const decrypted = service.decrypt(encrypted);
      expect(decrypted).toBe(str);
    }
  });

  it('INVARIANT: generated TOTP tokens are always 6 digits', async () => {
    const service = createTestService();

    for (let i = 0; i < 20; i++) {
      const secret = await service.generateSecret(`user${i}`, `user${i}@example.com`);
      const token = service.generateToken(secret);
      expect(token).toMatch(/^\d{6}$/);
    }
  });
});
