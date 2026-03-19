/**
 * Rickydata Security Kernel
 *
 * Provides:
 * - AES-256-GCM encryption/decryption
 * - TPM-based sealing/unsealing (with mock support)
 * - Sign-to-derive key derivation (user-controlled encryption)
 * - HKDF key derivation from master key
 * - In-memory encryption (fresh random key each startup)
 */

// Encryption (TPM-sealed master key model - Agent Gateway)
export { encrypt, decrypt, secureWipe, secureWipeString } from './encryption.js';
export type { EncryptedData } from './types.js';

// In-Memory Encryption (fresh random key each startup - MCP Gateway)
export {
  encrypt as encryptInmem,
  decrypt as decryptInmem,
  secureWipe as secureWipeInmem,
  secureWipeString as secureWipeStringInmem,
  initMasterKey,
  deriveUserKey,
  computeVaultKey,
  clearMasterKey,
  isMasterKeyInitialized,
} from './encryption-inmem.js';

// TPM Sealer
export {
  checkTpmAvailability,
  enableTpmMock,
  disableTpmMock,
  isTpmMockEnabled,
  tpmSeal,
  tpmUnseal,
  sealMasterKey,
  unsealMasterKey,
  hasSealedMasterKey,
  removeSealedMasterKey,
} from './tpm-sealer.js';
export type { TpmSealedData, TpmAvailability } from './types.js';

// Sign-to-Derive
export { deriveKeyFromSignature, encryptWithSignature, decryptWithSignature } from './sign-to-derive.js';
export type { SignToDeriveResult } from './types.js';

// Constants
export {
  ALGORITHM,
  HASH_ALGORITHM,
  KEY_LENGTH,
  IV_LENGTH,
  AUTH_TAG_LENGTH,
  DEFAULT_KEY_INFO,
  TPM_VERSION,
} from './constants.js';
