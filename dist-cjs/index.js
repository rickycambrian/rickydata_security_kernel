"use strict";
/**
 * Rickydata Security Kernel
 *
 * Provides:
 * - AES-256-GCM encryption/decryption
 * - TPM2 policy-PCR sealing/unsealing (mock mode only for tests)
 * - Sign-to-derive key derivation (signature-derived encryption)
 * - HKDF key derivation from master key
 * - In-memory encryption (fresh random key each startup)
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.TPM_VERSION = exports.DEFAULT_KEY_INFO = exports.AUTH_TAG_LENGTH = exports.IV_LENGTH = exports.KEY_LENGTH = exports.HASH_ALGORITHM = exports.ALGORITHM = exports.decryptWithSignature = exports.encryptWithSignature = exports.deriveKeyFromSignature = exports.removeSealedMasterKey = exports.hasSealedMasterKey = exports.unsealMasterKey = exports.sealMasterKey = exports.tpmUnseal = exports.tpmSeal = exports.isTpmMockEnabled = exports.disableTpmMock = exports.enableTpmMock = exports.checkTpmAvailability = exports.isMasterKeyInitialized = exports.clearMasterKey = exports.computeVaultKey = exports.deriveUserKey = exports.initMasterKey = exports.secureWipeStringInmem = exports.secureWipeInmem = exports.decryptInmem = exports.encryptInmem = exports.secureWipeString = exports.secureWipe = exports.decrypt = exports.encrypt = void 0;
// Encryption (TPM-sealed master key model - Agent Gateway)
var encryption_js_1 = require("./encryption.js");
Object.defineProperty(exports, "encrypt", { enumerable: true, get: function () { return encryption_js_1.encrypt; } });
Object.defineProperty(exports, "decrypt", { enumerable: true, get: function () { return encryption_js_1.decrypt; } });
Object.defineProperty(exports, "secureWipe", { enumerable: true, get: function () { return encryption_js_1.secureWipe; } });
Object.defineProperty(exports, "secureWipeString", { enumerable: true, get: function () { return encryption_js_1.secureWipeString; } });
// In-Memory Encryption (fresh random key each startup - MCP Gateway)
var encryption_inmem_js_1 = require("./encryption-inmem.js");
Object.defineProperty(exports, "encryptInmem", { enumerable: true, get: function () { return encryption_inmem_js_1.encrypt; } });
Object.defineProperty(exports, "decryptInmem", { enumerable: true, get: function () { return encryption_inmem_js_1.decrypt; } });
Object.defineProperty(exports, "secureWipeInmem", { enumerable: true, get: function () { return encryption_inmem_js_1.secureWipe; } });
Object.defineProperty(exports, "secureWipeStringInmem", { enumerable: true, get: function () { return encryption_inmem_js_1.secureWipeString; } });
Object.defineProperty(exports, "initMasterKey", { enumerable: true, get: function () { return encryption_inmem_js_1.initMasterKey; } });
Object.defineProperty(exports, "deriveUserKey", { enumerable: true, get: function () { return encryption_inmem_js_1.deriveUserKey; } });
Object.defineProperty(exports, "computeVaultKey", { enumerable: true, get: function () { return encryption_inmem_js_1.computeVaultKey; } });
Object.defineProperty(exports, "clearMasterKey", { enumerable: true, get: function () { return encryption_inmem_js_1.clearMasterKey; } });
Object.defineProperty(exports, "isMasterKeyInitialized", { enumerable: true, get: function () { return encryption_inmem_js_1.isMasterKeyInitialized; } });
// TPM Sealer
var tpm_sealer_js_1 = require("./tpm-sealer.js");
Object.defineProperty(exports, "checkTpmAvailability", { enumerable: true, get: function () { return tpm_sealer_js_1.checkTpmAvailability; } });
Object.defineProperty(exports, "enableTpmMock", { enumerable: true, get: function () { return tpm_sealer_js_1.enableTpmMock; } });
Object.defineProperty(exports, "disableTpmMock", { enumerable: true, get: function () { return tpm_sealer_js_1.disableTpmMock; } });
Object.defineProperty(exports, "isTpmMockEnabled", { enumerable: true, get: function () { return tpm_sealer_js_1.isTpmMockEnabled; } });
Object.defineProperty(exports, "tpmSeal", { enumerable: true, get: function () { return tpm_sealer_js_1.tpmSeal; } });
Object.defineProperty(exports, "tpmUnseal", { enumerable: true, get: function () { return tpm_sealer_js_1.tpmUnseal; } });
Object.defineProperty(exports, "sealMasterKey", { enumerable: true, get: function () { return tpm_sealer_js_1.sealMasterKey; } });
Object.defineProperty(exports, "unsealMasterKey", { enumerable: true, get: function () { return tpm_sealer_js_1.unsealMasterKey; } });
Object.defineProperty(exports, "hasSealedMasterKey", { enumerable: true, get: function () { return tpm_sealer_js_1.hasSealedMasterKey; } });
Object.defineProperty(exports, "removeSealedMasterKey", { enumerable: true, get: function () { return tpm_sealer_js_1.removeSealedMasterKey; } });
// Sign-to-Derive
var sign_to_derive_js_1 = require("./sign-to-derive.js");
Object.defineProperty(exports, "deriveKeyFromSignature", { enumerable: true, get: function () { return sign_to_derive_js_1.deriveKeyFromSignature; } });
Object.defineProperty(exports, "encryptWithSignature", { enumerable: true, get: function () { return sign_to_derive_js_1.encryptWithSignature; } });
Object.defineProperty(exports, "decryptWithSignature", { enumerable: true, get: function () { return sign_to_derive_js_1.decryptWithSignature; } });
// Constants
var constants_js_1 = require("./constants.js");
Object.defineProperty(exports, "ALGORITHM", { enumerable: true, get: function () { return constants_js_1.ALGORITHM; } });
Object.defineProperty(exports, "HASH_ALGORITHM", { enumerable: true, get: function () { return constants_js_1.HASH_ALGORITHM; } });
Object.defineProperty(exports, "KEY_LENGTH", { enumerable: true, get: function () { return constants_js_1.KEY_LENGTH; } });
Object.defineProperty(exports, "IV_LENGTH", { enumerable: true, get: function () { return constants_js_1.IV_LENGTH; } });
Object.defineProperty(exports, "AUTH_TAG_LENGTH", { enumerable: true, get: function () { return constants_js_1.AUTH_TAG_LENGTH; } });
Object.defineProperty(exports, "DEFAULT_KEY_INFO", { enumerable: true, get: function () { return constants_js_1.DEFAULT_KEY_INFO; } });
Object.defineProperty(exports, "TPM_VERSION", { enumerable: true, get: function () { return constants_js_1.TPM_VERSION; } });
//# sourceMappingURL=index.js.map