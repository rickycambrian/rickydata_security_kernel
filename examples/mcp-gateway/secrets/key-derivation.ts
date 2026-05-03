/**
 * HKDF Key Derivation
 *
 * Derives per-user encryption keys from a master key using HKDF.
 * Each user (identified by wallet address) gets a unique derived key.
 *
 * The master key is always a fresh 32-byte random value generated at startup.
 * Since the vault is purely in-memory (restart = clean slate), a random key
 * provides maximum security with zero operational burden — no secrets to
 * leak, steal, or misconfigure.
 *
 * This module wraps the @rickydata/security-kernel in-memory key derivation.
 * The security kernel provides the same HKDF implementation but allows
 * public auditability - both Agent Gateway and MCP Gateway use the same
 * crypto code.
 */

import {
  initMasterKey as skInitMasterKey,
  deriveUserKey as skDeriveUserKey,
  computeVaultKey as skComputeVaultKey,
  clearMasterKey as skClearMasterKey,
  isMasterKeyInitialized as skIsMasterKeyInitialized,
} from '@rickydata/security-kernel';

// Re-export key derivation functions
export const initMasterKey = skInitMasterKey;
export const deriveUserKey = skDeriveUserKey;
export const computeVaultKey = skComputeVaultKey;
export const clearMasterKey = skClearMasterKey;
export const isMasterKeyInitialized = skIsMasterKeyInitialized;