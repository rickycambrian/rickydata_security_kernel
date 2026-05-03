/**
 * Secret Management Types
 *
 * Simplified types for BYOK (Bring Your Own Key) API key storage.
 * Each wallet can store one Anthropic API key.
 */

export interface EncryptedApiKey {
  encryptedValue: Buffer;
  iv: Buffer;
  authTag: Buffer;
  createdAt: Date;
  lastUsedAt: Date;
}

export interface UserKeyVault {
  vaultKeyPrefix: string;  // First 8 chars of HMAC vault key (for logs only)
  userSalt: Buffer;        // 32 cryptographically random bytes for HKDF salt
  createdAt: Date;
  lastAccessAt: Date;
  apiKey: EncryptedApiKey | null;
}
