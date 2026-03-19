/**
 * In-Memory AES-256-GCM Encryption Utilities
 *
 * Provides secure encryption/decryption with authentication using fresh random
 * master keys on each startup. This approach provides maximum security because
 * there is no persistent key to steal - the master key is generated fresh
 * every time the service starts.
 *
 * This is the encryption model used by the MCP Gateway TEE.
 */

import * as crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;       // GCM standard IV length
const AUTH_TAG_LENGTH = 16; // GCM standard auth tag length

export interface EncryptedData {
  encrypted: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

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

// HKDF Key Derivation (for in-memory master key model)
const HASH_ALGORITHM = 'sha256';
const KEY_LENGTH = 32;
const INFO = 'mcp-gateway-secrets';

// Master key — fresh random bytes each startup
let masterKey: Buffer | null = null;

/**
 * Initializes the key derivation system with a cryptographically random master key.
 * Must be called before any key derivation operations.
 *
 * Generates a fresh 32-byte random key every time. The vault is in-memory only,
 * so there's no need for a persistent key — random auto-rotation on restart is
 * the most secure option.
 */
export function initMasterKey(): void {
  masterKey = crypto.randomBytes(32);
  console.log('[KEY-DERIVATION] Master key initialized (random)');
}

/**
 * Derives a user-specific encryption key from the master key.
 *
 * Uses HKDF with a per-user random salt concatenated with the wallet address
 * as the HKDF salt, and an optional serverId in the info parameter for
 * per-server key scoping.
 *
 * @param walletAddress - User's Ethereum wallet address (0x-prefixed)
 * @param userSalt - 32-byte per-user random salt
 * @param serverId - Optional server ID for per-server key scoping
 * @returns 32-byte derived key
 */
export function deriveUserKey(
  walletAddress: string,
  userSalt: Buffer,
  serverId?: string
): Buffer {
  if (!masterKey) {
    throw new Error('Master key not initialized. Call initMasterKey() first.');
  }

  // Normalize wallet address to lowercase
  const normalizedAddress = walletAddress.toLowerCase();

  // Combine per-user random salt with wallet address for HKDF salt
  const salt = Buffer.concat([userSalt, Buffer.from(normalizedAddress)]);

  // Use serverId in info for per-server key scoping
  const info = serverId ? `${INFO}:${serverId}` : INFO;

  // Use HKDF to derive a unique key for this user (and optionally server)
  const derivedKey = crypto.hkdfSync(
    HASH_ALGORITHM,
    masterKey,
    salt,  // salt: userSalt || walletAddress
    info,  // info: 'mcp-gateway-secrets[:serverId]'
    KEY_LENGTH
  );

  return Buffer.from(derivedKey);
}

/**
 * Computes an HMAC-SHA256 vault lookup key from a wallet address.
 * Used instead of storing plaintext wallet addresses as Map keys.
 *
 * @param walletAddress - User's Ethereum wallet address
 * @returns Hex string HMAC digest
 */
export function computeVaultKey(walletAddress: string): string {
  if (!masterKey) {
    throw new Error('Master key not initialized. Call initMasterKey() first.');
  }

  return crypto
    .createHmac('sha256', masterKey)
    .update(walletAddress.toLowerCase())
    .digest('hex');
}

/**
 * Clears the master key from memory.
 * Call this when shutting down the gateway.
 */
export function clearMasterKey(): void {
  if (masterKey) {
    masterKey.fill(0);
    masterKey = null;
  }
}

/**
 * Checks if the master key has been initialized.
 */
export function isMasterKeyInitialized(): boolean {
  return masterKey !== null;
}
