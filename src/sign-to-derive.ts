/**
 * Sign-to-Derive Key Derivation
 *
 * Derives an encryption key from an Ethereum signature.
 * This enables true user-controlled encryption:
 * - User signs a message with their wallet
 * - Signature is used to derive the encryption key
 * - Only the user can encrypt/decrypt (operator cannot read)
 */

import * as crypto from 'crypto';
import { encrypt, decrypt } from './encryption.js';
import type { SignToDeriveResult } from './types.js';

/**
 * Derives an encryption key from an Ethereum signature.
 *
 * Uses SHA-256 hash of the signature components to derive a 32-byte key.
 * This is deterministic and portable across all Node.js versions.
 *
 * @param signature - Ethereum signature (65 bytes: r, s, v)
 * @returns 32-byte derived key
 */
export function deriveKeyFromSignature(signature: string): Buffer {
  // Normalize signature (remove 0x prefix if present)
  const normalizedSig = signature.startsWith('0x') ? signature.slice(2) : signature;

  // Ensure signature is valid length (65 bytes = 130 hex chars)
  if (normalizedSig.length !== 130) {
    throw new Error('Invalid signature length: expected 65 bytes (130 hex chars)');
  }

  // Parse signature components
  const r = normalizedSig.slice(0, 64);
  const s = normalizedSig.slice(64, 128);
  const v = normalizedSig.slice(128, 130);

  // Use SHA-256 to derive a deterministic 32-byte key from the signature
  // This is deterministic and works across all Node.js versions
  const hash = crypto.createHash('sha256');
  hash.update(Buffer.from(r + s + v, 'hex'));
  const derived = hash.digest();

  return Buffer.from(derived);
}

/**
 * Encrypts a value using AES-256-GCM with a signature-derived key.
 *
 * @param plaintext - The value to encrypt
 * @param signature - Ethereum signature used to derive the key
 * @returns Object containing encrypted data, IV, auth tag (all base64 encoded)
 */
export function encryptWithSignature(
  plaintext: string,
  signature: string
): SignToDeriveResult {
  const key = deriveKeyFromSignature(signature);
  const { encrypted, iv, authTag } = encrypt(plaintext, key);

  return {
    encrypted: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
  };
}

/**
 * Decrypts a value using AES-256-GCM with a signature-derived key.
 *
 * @param encryptedBase64 - Base64 encoded encrypted data
 * @param ivBase64 - Base64 encoded IV
 * @param authTagBase64 - Base64 encoded auth tag
 * @param signature - Ethereum signature used to derive the key
 * @returns Decrypted plaintext
 */
export function decryptWithSignature(
  encryptedBase64: string,
  ivBase64: string,
  authTagBase64: string,
  signature: string
): string {
  const key = deriveKeyFromSignature(signature);

  return decrypt(
    Buffer.from(encryptedBase64, 'base64'),
    Buffer.from(ivBase64, 'base64'),
    Buffer.from(authTagBase64, 'base64'),
    key
  );
}
