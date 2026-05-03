/**
 * AES-256-GCM Encryption Utilities
 *
 * Provides secure encryption/decryption with authentication.
 * Uses Node.js built-in crypto module.
 *
 * This module wraps the @rickydata/security-kernel in-memory encryption model.
 * The security kernel provides the same AES-256-GCM implementation but
 * allows public auditability - both Agent Gateway and MCP Gateway use
 * the same crypto code.
 */

import {
  encryptInmem,
  decryptInmem,
  secureWipe as secureWipeBuffer,
  secureWipeStringInmem,
} from '@rickydata/security-kernel';

export type { EncryptedData } from '@rickydata/security-kernel';

// Re-export encryption functions with same names as before
export const encrypt = encryptInmem;
export const decrypt = decryptInmem;
export const secureWipe = secureWipeBuffer;
export const secureWipeString = secureWipeStringInmem;