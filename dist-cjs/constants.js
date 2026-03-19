"use strict";
/**
 * Security Kernel - Constants
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.TPM_VERSION = exports.DEFAULT_KEY_INFO = exports.AUTH_TAG_LENGTH = exports.IV_LENGTH = exports.KEY_LENGTH = exports.HASH_ALGORITHM = exports.ALGORITHM = void 0;
exports.ALGORITHM = 'aes-256-gcm';
exports.HASH_ALGORITHM = 'sha256';
exports.KEY_LENGTH = 32; // 256 bits for AES-256
exports.IV_LENGTH = 12; // GCM standard IV length
exports.AUTH_TAG_LENGTH = 16; // GCM standard auth tag length
exports.DEFAULT_KEY_INFO = 'rickydata-security-kernel';
exports.TPM_VERSION = 1;
//# sourceMappingURL=constants.js.map