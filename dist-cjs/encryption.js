"use strict";
/**
 * AES-256-GCM Encryption Utilities
 *
 * Provides secure encryption/decryption with authentication.
 * Uses Node.js built-in crypto module.
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
const crypto = __importStar(require("crypto"));
const constants_js_1 = require("./constants.js");
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
    const iv = crypto.randomBytes(constants_js_1.IV_LENGTH);
    // Create cipher
    const cipher = crypto.createCipheriv(constants_js_1.ALGORITHM, key, iv, {
        authTagLength: constants_js_1.AUTH_TAG_LENGTH,
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
    const decipher = crypto.createDecipheriv(constants_js_1.ALGORITHM, key, iv, {
        authTagLength: constants_js_1.AUTH_TAG_LENGTH,
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
//# sourceMappingURL=encryption.js.map