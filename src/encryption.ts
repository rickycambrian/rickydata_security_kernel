/**
 * AES-256-GCM Encryption Utilities
 *
 * Provides secure encryption/decryption with authentication.
 * Uses Node.js built-in crypto module.
 */

import * as crypto from 'crypto';
import { ALGORITHM, IV_LENGTH, AUTH_TAG_LENGTH } from './constants.js';
import type { EncryptedData } from './types.js';

export { EncryptedData };

/**
 * Encrypts a string value using AES-256-GCM
 *
 * @param plaintext - The value to encrypt
 * @param key - 32-byte encryption key
 * @returns Encrypted data with IV and auth tag
 */
export function encrypt(plaintext: string, key: Buffer): EncryptedData {
  if (key.length !== 32) {
    throw new Error('Encryption key must be 32 bytes');
  }

  // Generate random IV
  const iv = crypto.randomBytes(IV_LENGTH);

  // Create cipher
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  // Encrypt
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  // Get auth tag
  const authTag = cipher.getAuthTag();

  return { encrypted, iv, authTag };
}

/**
 * Decrypts AES-256-GCM encrypted data
 *
 * @param encrypted - The encrypted buffer
 * @param iv - The initialization vector
 * @param authTag - The authentication tag
 * @param key - 32-byte encryption key
 * @returns Decrypted plaintext
 */
export function decrypt(
  encrypted: Buffer,
  iv: Buffer,
  authTag: Buffer,
  key: Buffer
): string {
  if (key.length !== 32) {
    throw new Error('Encryption key must be 32 bytes');
  }

  // Create decipher
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  // Set auth tag for verification
  decipher.setAuthTag(authTag);

  // Decrypt
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

/**
 * Securely clears a buffer by overwriting with zeros.
 * Call this after using decrypted secrets.
 *
 * @param buffer - Buffer to clear
 */
export function secureWipe(buffer: Buffer): void {
  buffer.fill(0);
}

/**
 * Securely clears a string by creating a buffer and wiping.
 * Note: JavaScript strings are immutable, so this creates a new
 * buffer from the string and wipes it. The original string may
 * still exist in memory until GC runs.
 *
 * For true security, avoid storing decrypted secrets as strings
 * and work with buffers directly where possible.
 */
export function secureWipeString(str: string): void {
  const buffer = Buffer.from(str, 'utf8');
  secureWipe(buffer);
}
