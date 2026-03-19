"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.secureWipe = secureWipe;
exports.secureWipeString = secureWipeString;
exports.initMasterKey = initMasterKey;
exports.deriveUserKey = deriveUserKey;
exports.computeVaultKey = computeVaultKey;
exports.clearMasterKey = clearMasterKey;
exports.isMasterKeyInitialized = isMasterKeyInitialized;
const crypto = __importStar(require("crypto"));
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // GCM standard IV length
const AUTH_TAG_LENGTH = 16; // GCM standard auth tag length
/**
 * Encrypts a string value using AES-256-GCM
 *
 * @param plaintext - The value to encrypt
 * @param key - 32-byte encryption key
 * @returns Encrypted data with IV and auth tag
 */
function encrypt(plaintext, key) {
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
function decrypt(encrypted, iv, authTag, key) {
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
function secureWipe(buffer) {
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
function secureWipeString(str) {
    const buffer = Buffer.from(str, 'utf8');
    secureWipe(buffer);
}
// HKDF Key Derivation (for in-memory master key model)
const HASH_ALGORITHM = 'sha256';
const KEY_LENGTH = 32;
const INFO = 'mcp-gateway-secrets';
// Master key — fresh random bytes each startup
let masterKey = null;
/**
 * Initializes the key derivation system with a cryptographically random master key.
 * Must be called before any key derivation operations.
 *
 * Generates a fresh 32-byte random key every time. The vault is in-memory only,
 * so there's no need for a persistent key — random auto-rotation on restart is
 * the most secure option.
 */
function initMasterKey() {
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
function deriveUserKey(walletAddress, userSalt, serverId) {
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
    const derivedKey = crypto.hkdfSync(HASH_ALGORITHM, masterKey, salt, // salt: userSalt || walletAddress
    info, // info: 'mcp-gateway-secrets[:serverId]'
    KEY_LENGTH);
    return Buffer.from(derivedKey);
}
/**
 * Computes an HMAC-SHA256 vault lookup key from a wallet address.
 * Used instead of storing plaintext wallet addresses as Map keys.
 *
 * @param walletAddress - User's Ethereum wallet address
 * @returns Hex string HMAC digest
 */
function computeVaultKey(walletAddress) {
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
function clearMasterKey() {
    if (masterKey) {
        masterKey.fill(0);
        masterKey = null;
    }
}
/**
 * Checks if the master key has been initialized.
 */
function isMasterKeyInitialized() {
    return masterKey !== null;
}
//# sourceMappingURL=encryption-inmem.js.map