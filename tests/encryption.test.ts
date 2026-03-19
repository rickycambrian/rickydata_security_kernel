import { describe, it, expect, beforeEach } from 'vitest';
import { encrypt, decrypt, secureWipe } from '../src/encryption.js';

describe('encryption', () => {
  const key = Buffer.from('a'.repeat(32), 'utf8');

  describe('encrypt/decrypt', () => {
    it('should encrypt and decrypt a string', () => {
      const plaintext = 'Hello, World!';
      const { encrypted, iv, authTag } = encrypt(plaintext, key);

      expect(encrypted.length).toBeGreaterThan(0);
      expect(iv.length).toBe(12);
      expect(authTag.length).toBe(16);

      const decrypted = decrypt(encrypted, iv, authTag, key);
      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertext each time (random IV)', () => {
      const plaintext = 'Same message';

      const result1 = encrypt(plaintext, key);
      const result2 = encrypt(plaintext, key);

      expect(result1.encrypted.equals(result2.encrypted)).toBe(false);
    });

    it('should handle unicode characters', () => {
      const plaintext = 'Hello 你好 🌍 🔐';
      const { encrypted, iv, authTag } = encrypt(plaintext, key);

      const decrypted = decrypt(encrypted, iv, authTag, key);
      expect(decrypted).toBe(plaintext);
    });

    it('should handle long strings', () => {
      const plaintext = 'a'.repeat(10000);
      const { encrypted, iv, authTag } = encrypt(plaintext, key);

      const decrypted = decrypt(encrypted, iv, authTag, key);
      expect(decrypted).toBe(plaintext);
    });

    it('should throw on invalid key length', () => {
      const shortKey = Buffer.from('short');
      expect(() => encrypt('test', shortKey)).toThrow('Encryption key must be 32 bytes');
    });

    it('should throw on invalid key length during decryption', () => {
      const shortKey = Buffer.from('short');
      const { encrypted, iv, authTag } = encrypt('test', key);
      expect(() => decrypt(encrypted, iv, authTag, shortKey)).toThrow('Encryption key must be 32 bytes');
    });

    it('should detect tampered ciphertext (wrong auth tag)', () => {
      const plaintext = 'Secret message';
      const { encrypted, iv, authTag } = encrypt(plaintext, key);

      // Tamper with the ciphertext
      encrypted[0] = encrypted[0] ^ 0xff;

      expect(() => decrypt(encrypted, iv, authTag, key)).toThrow();
    });
  });

  describe('secureWipe', () => {
    it('should overwrite buffer with zeros', () => {
      const buffer = Buffer.from('sensitive data');
      const original = buffer.toString();

      secureWipe(buffer);

      // All bytes should be zero
      expect(buffer.every(b => b === 0)).toBe(true);
    });
  });
});
