"use strict";
/**
 * Sign-to-Derive Key Derivation
 *
 * Derives an encryption key from an Ethereum signature.
 * This enables true user-controlled encryption:
 * - User signs a message with their wallet
 * - Signature is used to derive the encryption key
 * - Only the user can encrypt/decrypt (operator cannot read)
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
exports.deriveKeyFromSignature = deriveKeyFromSignature;
exports.encryptWithSignature = encryptWithSignature;
exports.decryptWithSignature = decryptWithSignature;
const crypto = __importStar(require("crypto"));
const encryption_js_1 = require("./encryption.js");
/**
 * Derives an encryption key from an Ethereum signature.
 *
 * Uses SHA-256 hash of the signature components to derive a 32-byte key.
 * This is deterministic and portable across all Node.js versions.
 *
 * @param signature - Ethereum signature (65 bytes: r, s, v)
 * @returns 32-byte derived key
 */
function deriveKeyFromSignature(signature) {
    // Normalize signature (remove 0x prefix if present)
    const normalizedSig = signature.startsWith('0x') ? signature.slice(2) : signature;
    // Ensure signature is valid length (65 bytes = 130 hex chars)
    if (normalizedSig.length !== 130) {
        throw new Error('Invalid signature length: expected 65 bytes (130 hex chars)');
    }
    if (!/^[0-9a-fA-F]{130}$/.test(normalizedSig)) {
        throw new Error('Invalid signature format: expected hex-encoded Ethereum signature');
    }
    // Parse signature components
    const r = normalizedSig.slice(0, 64);
    const s = normalizedSig.slice(64, 128);
    const v = normalizedSig.slice(128, 130);
    // Use SHA-256 to derive a deterministic 32-byte key from the signature
    // This is deterministic and works across all Node.js versions
    const hash = crypto.createHash('sha256');
    hash.update(Buffer.from(r + s + v, 'hex'));
    const derived = hash.digest();
    return Buffer.from(derived);
}
/**
 * Encrypts a value using AES-256-GCM with a signature-derived key.
 *
 * @param plaintext - The value to encrypt
 * @param signature - Ethereum signature used to derive the key
 * @returns Object containing encrypted data, IV, auth tag (all base64 encoded)
 */
function encryptWithSignature(plaintext, signature) {
    const key = deriveKeyFromSignature(signature);
    try {
        const { encrypted, iv, authTag } = (0, encryption_js_1.encrypt)(plaintext, key);
        return {
            encrypted: encrypted.toString('base64'),
            iv: iv.toString('base64'),
            authTag: authTag.toString('base64'),
        };
    }
    finally {
        key.fill(0);
    }
}
/**
 * Decrypts a value using AES-256-GCM with a signature-derived key.
 *
 * @param encryptedBase64 - Base64 encoded encrypted data
 * @param ivBase64 - Base64 encoded IV
 * @param authTagBase64 - Base64 encoded auth tag
 * @param signature - Ethereum signature used to derive the key
 * @returns Decrypted plaintext
 */
function decryptWithSignature(encryptedBase64, ivBase64, authTagBase64, signature) {
    const key = deriveKeyFromSignature(signature);
    try {
        return (0, encryption_js_1.decrypt)(Buffer.from(encryptedBase64, 'base64'), Buffer.from(ivBase64, 'base64'), Buffer.from(authTagBase64, 'base64'), key);
    }
    finally {
        key.fill(0);
    }
}
//# sourceMappingURL=sign-to-derive.js.map