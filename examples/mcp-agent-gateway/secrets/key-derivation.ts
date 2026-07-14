/**
 * HKDF Key Derivation
 *
 * Derives per-user encryption keys from a master key using HKDF.
 * Each user (identified by wallet address) gets a unique derived key.
 *
 * The master key can be either:
 * - TPM-sealed: Persists across restarts, protected by hardware TPM
 * - Random: Generated fresh each startup (in-memory only, no persistence)
 *
 * Sign-to-Derive Mode:
 * - User signs a message with their wallet
 * - The authorized runtime derives the encryption key in memory
 * - Persistent storage does not retain that derived key
 * - Wallet-authorized encryption at rest, not user-only E2EE
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import { encrypt, decrypt, checkTpmAvailability, unsealMasterKey, sealMasterKey, hasSealedMasterKey, deriveKeyFromSignature, encryptWithSignature, decryptWithSignature, HASH_ALGORITHM, KEY_LENGTH } from '@rickydata/security-kernel';
import { log } from '../utils/logger.js';

const INFO = 'agent-gateway-secrets';

// Master key — sealed to TPM or random bytes
let masterKey: Buffer | null = null;

// Path for sealed master key (set by initMasterKey)
let sealedKeyPath: string | null = null;

/**
 * Initializes the key derivation system.
 *
 * TPM Mode (preferred):
 * - Checks for existing TPM-sealed master key
 * - Unseals existing key OR creates new and seals it
 * - Container FAILS if TPM unavailable
 *
 * Fallback Mode (development only):
 * - Generates fresh random key each startup
 * - Use only when TPM is not available
 *
 * @param options - Initialization options
 * @param options.sealedKeyPath - Path to store/load TPM-sealed key
 * @param options.allowFallback - Allow random key fallback (default: false, set true for dev)
 */
export function initMasterKey(options?: { sealedKeyPath?: string; allowFallback?: boolean }): void {
  const sealPath = options?.sealedKeyPath || process.env.TPM_SEALED_KEY_PATH || '/var/lib/agent-gateway/secrets/master-key.sealed';
  // Auto-enable fallback in test environment
  const isTestEnv = process.env.NODE_ENV === 'test' || process.env.VITEST === 'true';
  const allowFallback = options?.allowFallback ?? (process.env.ALLOW_MASTER_KEY_FALLBACK === 'true' || isTestEnv);

  sealedKeyPath = sealPath;

  // Check TPM availability
  const tpmStatus = checkTpmAvailability();

  if (tpmStatus.available) {
    log('info', 'KeyDerivation', 'TPM available', { devicePath: tpmStatus.devicePath });

    // Try to load existing sealed key
    if (hasSealedMasterKey(sealPath)) {
      try {
        masterKey = unsealMasterKey(sealPath);
        log('info', 'KeyDerivation', 'Master key unsealed from TPM');
      } catch (err) {
        // Unseal failed — sealed file is corrupted or PCR context changed (e.g., VM stop/start).
        // BYOK vault (user API keys) is safe — it uses BYOK_VAULT_ENCRYPTION_KEY (env-derived),
        // which is independent of this master key.
        // Agent secrets encrypted with the OLD master key are unrecoverable without re-storing.
        // Rather than crashing the container (which blocks ALL users), remove the stale sealed
        // file and generate a fresh key so the system can start.
        log('error', 'KeyDerivation', 'WARNING: Failed to unseal master key from TPM', { error: err instanceof Error ? err.message : String(err) });
        log('error', 'KeyDerivation', 'Removing stale sealed key and generating fresh master key.');
        log('error', 'KeyDerivation', 'Agent secrets from previous sessions may need to be re-stored by users.');
        log('error', 'KeyDerivation', 'BYOK API key vault is UNAFFECTED (uses BYOK_VAULT_ENCRYPTION_KEY).');
        try {
          fs.unlinkSync(sealPath);
          log('info', 'KeyDerivation', 'Removed stale sealed key', { sealPath });
        } catch (unlinkErr) {
          log('error', 'KeyDerivation', 'Could not remove stale sealed key', { error: unlinkErr instanceof Error ? unlinkErr.message : String(unlinkErr) });
        }
        // Fall through to the "no existing sealed key" branch below
      }
    }
    if (!masterKey) {
      // First-time setup: generate new key and seal it to disk via TPM.
      // If sealing fails (e.g. /var/lib is read-only after a fresh deploy where PCR context
      // is not yet populated), fall back to an in-memory key. This is safe because the
      // vault encryption itself uses BYOK_VAULT_ENCRYPTION_KEY (env-derived), which is
      // independent of the masterKey sealed here.
      log('info', 'KeyDerivation', 'No existing sealed key found - generating new master key');
      masterKey = crypto.randomBytes(32);
      try {
        sealMasterKey(masterKey, sealPath);
        log('info', 'KeyDerivation', 'New master key sealed to TPM');
      } catch (sealErr) {
        log('error', 'KeyDerivation', 'CRITICAL: Failed to seal master key', { error: sealErr instanceof Error ? sealErr.message : String(sealErr) });
        log('error', 'KeyDerivation', 'Master key is IN-MEMORY ONLY — agent secrets encrypted with this key will be LOST on restart.');
        log('error', 'KeyDerivation', 'Ensure /var/lib/agent-gateway/secrets/ is a writable volume mount.');
        // Keep the in-memory masterKey so the system can start, but agent secret persistence
        // across restarts is broken. BYOK API key vault is unaffected (uses BYOK_VAULT_ENCRYPTION_KEY directly).
      }
    }
  } else if (allowFallback) {
    // Development fallback: random key (not persistent)
    if (!isTestEnv) {
      log('warn', 'KeyDerivation', 'TPM not available - using random fallback (NOT PERSISTENT)');
    }
    masterKey = crypto.randomBytes(32);
  } else {
    // Production: TPM must be available
    log('error', 'KeyDerivation', 'CRITICAL: TPM not available and fallback disabled');
    throw new Error(
      'TPM is required for master key initialization. ' +
      'Container cannot start without TPM protection. ' +
      `TPM check: ${tpmStatus.reason || 'not available'}`
    );
  }

  log('info', 'KeyDerivation', 'Master key initialized');
}

/**
 * Derives a user-specific encryption key from the master key.
 *
 * Uses HKDF with a per-user random salt concatenated with the wallet address
 * as the HKDF salt.
 *
 * @param walletAddress - User's Ethereum wallet address (0x-prefixed)
 * @param userSalt - 32-byte per-user random salt
 * @returns 32-byte derived key
 */
export function deriveUserKey(
  walletAddress: string,
  userSalt: Buffer
): Buffer {
  if (!masterKey) {
    throw new Error('Master key not initialized. Call initMasterKey() first.');
  }

  // Normalize wallet address to lowercase
  const normalizedAddress = walletAddress.toLowerCase();

  // Combine per-user random salt with wallet address for HKDF salt
  const salt = Buffer.concat([userSalt, Buffer.from(normalizedAddress)]);

  // Use HKDF to derive a unique key for this user
  const derivedKey = crypto.hkdfSync(
    HASH_ALGORITHM,
    masterKey,
    salt,  // salt: userSalt || walletAddress
    INFO,  // info: 'agent-gateway-secrets'
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

// Re-export sign-to-derive functions from security-kernel
export { deriveKeyFromSignature, encryptWithSignature, decryptWithSignature };
