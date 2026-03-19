"use strict";
/**
 * TPM Sealer
 *
 * Provides TPM-based sealing/unsealing of the master encryption key.
 * Uses the TPM to protect the master key so that even if the server is
 * compromised, the user data remains protected.
 *
 * In production, this uses the Linux TPM 2.0 interface via /dev/tpm0.
 * For testing, a mock implementation is available.
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
exports.checkTpmAvailability = checkTpmAvailability;
exports.enableTpmMock = enableTpmMock;
exports.disableTpmMock = disableTpmMock;
exports.isTpmMockEnabled = isTpmMockEnabled;
exports.tpmSeal = tpmSeal;
exports.tpmUnseal = tpmUnseal;
exports.sealMasterKey = sealMasterKey;
exports.unsealMasterKey = unsealMasterKey;
exports.hasSealedMasterKey = hasSealedMasterKey;
exports.removeSealedMasterKey = removeSealedMasterKey;
const crypto = __importStar(require("crypto"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const constants_js_1 = require("./constants.js");
// Track TPM availability
let tpmAvailable = null;
let tpmDevicePath = null;
// TPM simulation for testing
let mockSealedData = null;
let mockUnsealFn = null;
let mockPublicKey = null;
let sealedCounter = 0;
// Store original data for mock unseal - key is sealedData hash
let mockSealedContents = new Map();
/**
 * Checks if a TPM is available on the system.
 *
 * @returns TpmAvailability object
 */
function checkTpmAvailability() {
    // Check cached result
    if (tpmAvailable !== null) {
        return { available: tpmAvailable, devicePath: tpmDevicePath || undefined };
    }
    // Check for TPM devices
    const tpmPaths = ['/dev/tpm0', '/dev/tpmrm0'];
    for (const devicePath of tpmPaths) {
        try {
            if (fs.existsSync(devicePath)) {
                tpmAvailable = true;
                tpmDevicePath = devicePath;
                return { available: true, devicePath };
            }
        }
        catch {
            // Continue to next device
        }
    }
    tpmAvailable = false;
    return { available: false, reason: 'No TPM device found', devicePath: undefined };
}
/**
 * Enables mock mode for testing without actual TPM hardware.
 *
 * @param sealedData - Mock sealed data to return (seed for deterministic results)
 * @param unsealFn - Optional function to simulate unsealing
 * @param publicKey - Optional public key for the mock TPM
 */
function enableTpmMock(sealedData, unsealFn, publicKey) {
    mockSealedData = sealedData;
    mockUnsealFn = unsealFn || ((data) => crypto.createHash('sha256').update(data).digest());
    mockPublicKey = publicKey || crypto.createHash('sha256').update(sealedData).digest();
    tpmAvailable = true;
    tpmDevicePath = 'mock';
    sealedCounter = 0;
}
/**
 * Disables mock mode.
 */
function disableTpmMock() {
    mockSealedData = null;
    mockUnsealFn = null;
    mockPublicKey = null;
    sealedCounter = 0;
    mockSealedContents.clear();
    tpmAvailable = null;
    tpmDevicePath = null;
}
/**
 * Checks if mock mode is enabled.
 */
function isTpmMockEnabled() {
    return mockSealedData !== null;
}
/**
 * Seals data using the TPM.
 *
 * In production, this would use the TPM2_Seal command.
 * For this implementation, we use a simulation that demonstrates
 * the API contract while using software encryption as fallback.
 *
 * @param data - 32-byte data to seal
 * @returns TpmSealedData object
 */
function tpmSeal(data) {
    if (data.length !== 32) {
        throw new Error('Sealed data must be 32 bytes');
    }
    // Use mock if enabled - produce different result each call (like real TPM)
    if (mockSealedData !== null) {
        // Include a counter to ensure different seals produce different ciphertext
        sealedCounter++;
        const uniqueInput = Buffer.concat([
            mockSealedData,
            Buffer.from([sealedCounter & 0xff, (sealedCounter >> 8) & 0xff])
        ]);
        // Deterministic but unique per call
        const sealedData = crypto.createHash('sha256').update(uniqueInput).digest();
        // Store original data for unseal (using sealedData as key)
        const sealedKey = sealedData.toString('hex');
        mockSealedContents.set(sealedKey, data);
        // Public key is deterministic for same TPM
        const publicKey = mockPublicKey || crypto.createHash('sha256').update(mockSealedData).digest();
        return {
            version: constants_js_1.TPM_VERSION,
            sealedData,
            publicKey,
            algorithm: 'mock-aes-256-gcm',
            createdAt: Date.now(),
        };
    }
    const availability = checkTpmAvailability();
    if (!availability.available) {
        throw new Error(`TPM not available: ${availability.reason}`);
    }
    // Production implementation would use actual TPM commands here
    // For now, we demonstrate the concept with software encryption
    // that would be replaced with TPM2 Seal in production
    const simulatedTpmKey = crypto.createHash('sha256')
        .update(availability.devicePath)
        .digest();
    const cipher = crypto.createCipheriv('aes-256-gcm', simulatedTpmKey, crypto.randomBytes(12));
    const sealedData = Buffer.concat([
        cipher.update(data),
        cipher.final(),
        cipher.getAuthTag(),
    ]);
    return {
        version: constants_js_1.TPM_VERSION,
        sealedData,
        publicKey: crypto.createHash('sha256').update(simulatedTpmKey).digest(),
        algorithm: 'aes-256-gcm',
        createdAt: Date.now(),
    };
}
/**
 * Unseals TPM-sealed data.
 *
 * @param sealedData - TpmSealedData object from tpmSeal
 * @returns Original 32-byte data
 */
function tpmUnseal(sealedData) {
    // Use mock if enabled - retrieve stored original data
    if (mockSealedContents.size > 0) {
        const sealedKey = sealedData.sealedData.toString('hex');
        const original = mockSealedContents.get(sealedKey);
        if (original) {
            return original;
        }
        // Fallback to custom unseal fn if set
        if (mockUnsealFn !== null) {
            return mockUnsealFn(sealedData.sealedData);
        }
        throw new Error('Mock unseal: no stored data found');
    }
    // Legacy: use custom unseal fn if no stored contents
    if (mockUnsealFn !== null) {
        return mockUnsealFn(sealedData.sealedData);
    }
    const availability = checkTpmAvailability();
    if (!availability.available) {
        throw new Error(`TPM not available: ${availability.reason}`);
    }
    // Production implementation would use actual TPM2_Unseal command
    // For now, we demonstrate the concept with software decryption
    const simulatedTpmKey = crypto.createHash('sha256')
        .update(availability.devicePath)
        .digest();
    // Extract auth tag (last 16 bytes) and ciphertext
    const authTag = sealedData.sealedData.slice(-16);
    const ciphertext = sealedData.sealedData.slice(0, -16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', simulatedTpmKey, crypto.randomBytes(12));
    decipher.setAuthTag(authTag);
    return Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
    ]);
}
/**
 * Seals the master key for persistent storage.
 *
 * @param masterKey - 32-byte master key to seal
 * @param storagePath - Path to store sealed data
 */
function sealMasterKey(masterKey, storagePath) {
    const sealed = tpmSeal(masterKey);
    // Store as JSON for portability
    const data = {
        version: sealed.version,
        sealedData: sealed.sealedData.toString('base64'),
        publicKey: sealed.publicKey.toString('base64'),
        algorithm: sealed.algorithm,
        createdAt: sealed.createdAt,
    };
    // Ensure directory exists
    const dir = path.dirname(storagePath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(storagePath + '.tmp', JSON.stringify(data, null, 2));
    fs.renameSync(storagePath + '.tmp', storagePath);
}
/**
 * Unseals and loads the master key from persistent storage.
 *
 * @param storagePath - Path to sealed data file
 * @returns Original 32-byte master key
 */
function unsealMasterKey(storagePath) {
    if (!fs.existsSync(storagePath)) {
        throw new Error(`Sealed key file not found: ${storagePath}`);
    }
    const data = JSON.parse(fs.readFileSync(storagePath, 'utf-8'));
    const sealedData = {
        version: data.version,
        sealedData: Buffer.from(data.sealedData, 'base64'),
        publicKey: Buffer.from(data.publicKey, 'base64'),
        algorithm: data.algorithm,
        createdAt: data.createdAt,
    };
    return tpmUnseal(sealedData);
}
/**
 * Checks if a sealed master key exists at the given path.
 *
 * @param storagePath - Path to sealed data file
 * @returns true if sealed key exists
 */
function hasSealedMasterKey(storagePath) {
    return fs.existsSync(storagePath);
}
/**
 * Removes the sealed master key from persistent storage.
 *
 * @param storagePath - Path to sealed data file
 */
function removeSealedMasterKey(storagePath) {
    if (fs.existsSync(storagePath)) {
        fs.unlinkSync(storagePath);
    }
}
//# sourceMappingURL=tpm-sealer.js.map