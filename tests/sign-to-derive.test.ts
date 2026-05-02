import { describe, it, expect } from 'vitest';
import { deriveKeyFromSignature, encryptWithSignature, decryptWithSignature } from '../src/sign-to-derive.js';
import { secureWipe } from '../src/encryption.js';

describe('sign-to-derive', () => {
  // Test signature: 65 bytes (130 hex chars)
  // This is a mock signature for testing
  const testSignature = '88'.repeat(65);

  describe('deriveKeyFromSignature', () => {
    it('should derive a 32-byte key from a valid signature', () => {
      const key = deriveKeyFromSignature(testSignature);
      expect(key.length).toBe(32);
    });

    it('should produce deterministic key (same sig = same key)', () => {
      const key1 = deriveKeyFromSignature(testSignature);
      const key2 = deriveKeyFromSignature(testSignature);
      expect(key1.equals(key2)).toBe(true);
    });

    it('should produce different keys for different signatures', () => {
      const key1 = deriveKeyFromSignature(testSignature);
      const key2 = deriveKeyFromSignature('aa'.repeat(65));
      expect(key1.equals(key2)).toBe(false);
    });

    it('should handle 0x-prefixed signature', () => {
      const key1 = deriveKeyFromSignature(testSignature);
      const key2 = deriveKeyFromSignature('0x' + testSignature);
      expect(key1.equals(key2)).toBe(true);
    });

    it('should throw on invalid signature length', () => {
      expect(() => deriveKeyFromSignature('abcd')).toThrow('Invalid signature length');
    });

    it('should throw on non-hex signatures with valid length', () => {
      expect(() => deriveKeyFromSignature('zz'.repeat(65))).toThrow('Invalid signature format');
    });

    it('should throw on wrong signature length', () => {
      expect(() => deriveKeyFromSignature('aa'.repeat(64))).toThrow('Invalid signature length');
      expect(() => deriveKeyFromSignature('aa'.repeat(66))).toThrow('Invalid signature length');
    });
  });

  describe('encryptWithSignature / decryptWithSignature', () => {
    const plaintext = 'My secret message';

    it('should encrypt and decrypt using signature-derived key', () => {
      const { encrypted, iv, authTag } = encryptWithSignature(plaintext, testSignature);

      expect(encrypted).toBeDefined();
      expect(iv).toBeDefined();
      expect(authTag).toBeDefined();

      const decrypted = decryptWithSignature(encrypted, iv, authTag, testSignature);
      expect(decrypted).toBe(plaintext);
    });

    it('should fail to decrypt with different signature', () => {
      const { encrypted, iv, authTag } = encryptWithSignature(plaintext, testSignature);
      const differentSig = 'ff'.repeat(65);

      expect(() => {
        decryptWithSignature(encrypted, iv, authTag, differentSig);
      }).toThrow();
    });

    it('should produce different ciphertext for same message (different IVs)', () => {
      const result1 = encryptWithSignature(plaintext, testSignature);
      const result2 = encryptWithSignature(plaintext, testSignature);

      expect(result1.encrypted).not.toBe(result2.encrypted);
    });

    it('should handle unicode content', () => {
      const unicodeText = '私密消息 🔐 你好世界';
      const { encrypted, iv, authTag } = encryptWithSignature(unicodeText, testSignature);

      const decrypted = decryptWithSignature(encrypted, iv, authTag, testSignature);
      expect(decrypted).toBe(unicodeText);
    });

    it('should return base64-encoded output', () => {
      const { encrypted, iv, authTag } = encryptWithSignature(plaintext, testSignature);

      // Should be valid base64
      expect(() => Buffer.from(encrypted, 'base64')).not.toThrow();
      expect(() => Buffer.from(iv, 'base64')).not.toThrow();
      expect(() => Buffer.from(authTag, 'base64')).not.toThrow();
    });
  });

  describe('signature lifecycle', () => {
    it('should fail to decrypt when a different signature is used', () => {
      const sigA = 'aa'.repeat(65);
      const sigB = 'bb'.repeat(65);

      // Encrypt with signature A
      const { encrypted, iv, authTag } = encryptWithSignature('top secret', sigA);

      // Decrypt with signature B must fail (different derived key)
      expect(() => {
        decryptWithSignature(encrypted, iv, authTag, sigB);
      }).toThrow();

      // Decrypt with signature A must succeed
      const result = decryptWithSignature(encrypted, iv, authTag, sigA);
      expect(result).toBe('top secret');
    });

    it('same signature always derives the same key (determinism across calls)', () => {
      const sig = 'cc'.repeat(65);

      const key1 = deriveKeyFromSignature(sig);
      const key2 = deriveKeyFromSignature(sig);
      const key3 = deriveKeyFromSignature(sig);

      expect(key1.equals(key2)).toBe(true);
      expect(key2.equals(key3)).toBe(true);
    });

    it('secureWipe clears the derived key buffer', () => {
      const sig = 'dd'.repeat(65);
      const key = deriveKeyFromSignature(sig);

      // Key should be non-zero before wipe
      expect(key.some(b => b !== 0)).toBe(true);

      secureWipe(key);

      // All bytes should be zero after wipe
      expect(key.every(b => b === 0)).toBe(true);
    });

    it('encrypt-decrypt round-trip preserves data integrity for multiple secrets', () => {
      const sig = 'ee'.repeat(65);
      const secrets = [
        'sk-ant-api03-secret-key-value',
        '{"password":"hunter2","token":"abc123"}',
        '',  // empty string
        'a'.repeat(10000),  // large payload
      ];

      for (const secret of secrets) {
        const { encrypted, iv, authTag } = encryptWithSignature(secret, sig);
        const decrypted = decryptWithSignature(encrypted, iv, authTag, sig);
        expect(decrypted).toBe(secret);
      }
    });
  });
});
