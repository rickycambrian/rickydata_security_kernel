/**
 * Security Kernel - Constants
 */

export const ALGORITHM = 'aes-256-gcm';
export const HASH_ALGORITHM = 'sha256';
export const KEY_LENGTH = 32; // 256 bits for AES-256
export const IV_LENGTH = 12;  // GCM standard IV length
export const AUTH_TAG_LENGTH = 16; // GCM standard auth tag length

export const DEFAULT_KEY_INFO = 'rickydata-security-kernel';

export const TPM_VERSION = 1;
