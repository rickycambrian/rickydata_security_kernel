/**
 * AES-256-GCM Encryption Utilities
 *
 * Provides secure encryption/decryption with authentication.
 * Uses @rickydata/security-kernel package.
 */

import { encrypt, decrypt, secureWipe, secureWipeString } from '@rickydata/security-kernel';

export type { EncryptedData } from '@rickydata/security-kernel';

export { encrypt, decrypt, secureWipe, secureWipeString };
