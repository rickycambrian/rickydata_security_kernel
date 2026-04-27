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
const os = __importStar(require("os"));
const child_process_1 = require("child_process");
const constants_js_1 = require("./constants.js");
const PCR_SELECTION = process.env.TPM_PCR_LIST || 'sha256:0,1,2,3,4,5,7';
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
    const requiredCommands = [
        'tpm2_getcap',
        'tpm2_createprimary',
        'tpm2_create',
        'tpm2_load',
        'tpm2_unseal',
        'tpm2_pcrread',
        'tpm2_createpolicy',
        'tpm2_startauthsession',
        'tpm2_policypcr',
        'tpm2_flushcontext',
    ];
    for (const command of requiredCommands) {
        if (!commandAvailable(command)) {
            tpmAvailable = false;
            return { available: false, reason: `${command} not found`, devicePath: undefined };
        }
    }
    const overridePath = process.env.RICKYDATA_TPM_DEVICE_PATH;
    const tpmPaths = overridePath ? [overridePath] : ['/dev/tpmrm0', '/dev/tpm0'];
    let lastProbeFailure;
    for (const devicePath of tpmPaths) {
        try {
            if (fs.existsSync(devicePath)) {
                const tcti = tctiForDevice(devicePath);
                execTpm('tpm2_getcap', ['properties-fixed'], { tcti });
                tpmAvailable = true;
                tpmDevicePath = devicePath;
                return { available: true, devicePath };
            }
        }
        catch (err) {
            lastProbeFailure = `TPM device probe failed for ${devicePath}: ${err instanceof Error ? err.message : String(err)}`;
        }
    }
    tpmAvailable = false;
    return { available: false, reason: lastProbeFailure || 'No TPM device found', devicePath: undefined };
}
function commandAvailable(command) {
    try {
        (0, child_process_1.execFileSync)('which', [command], { stdio: 'ignore' });
        return true;
    }
    catch {
        return false;
    }
}
function tctiForDevice(devicePath) {
    return `device:${devicePath}`;
}
function execTpm(command, args, options) {
    return (0, child_process_1.execFileSync)(command, args, {
        input: options?.input,
        env: {
            ...process.env,
            ...(options?.tcti ? { TPM2TOOLS_TCTI: options.tcti } : {}),
        },
        stdio: options?.input ? ['pipe', 'pipe', 'pipe'] : ['ignore', 'pipe', 'pipe'],
    });
}
function tryExecTpm(command, args, options) {
    try {
        execTpm(command, args, options);
    }
    catch {
        // TPM context cleanup is best effort.
    }
}
function mkTempDir() {
    const base = fs.existsSync('/dev/shm') ? '/dev/shm' : os.tmpdir();
    return fs.mkdtempSync(path.join(base, 'rickydata-tpm-'));
}
function cleanupTempDir(dir) {
    try {
        fs.rmSync(dir, { recursive: true, force: true });
    }
    catch {
        // Best effort only; temp files contain sealed blobs after successful cleanup.
    }
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
 * **Production path**: Uses TPM2_Seal via `/dev/tpm0` or `/dev/tpmrm0` to
 * hardware-bind the sealed blob to the platform's PCR state.
 *
 * **No software fallback**: Production fails closed if the TPM device or
 * required `tpm2-tools` commands are unavailable.
 *
 * **Mock mode**: When `enableTpmMock()` has been called, seal/unseal use
 * deterministic in-memory storage. This is the correct path for unit tests.
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
    const tcti = tctiForDevice(availability.devicePath);
    const tmpDir = mkTempDir();
    const primaryCtx = path.join(tmpDir, 'primary.ctx');
    const policyFile = path.join(tmpDir, 'pcr.policy');
    const pcrFile = path.join(tmpDir, 'pcr.bin');
    const inputFile = path.join(tmpDir, 'secret.bin');
    const publicFile = path.join(tmpDir, 'sealed.pub');
    const privateFile = path.join(tmpDir, 'sealed.priv');
    const sealedCtx = path.join(tmpDir, 'sealed.ctx');
    try {
        fs.writeFileSync(inputFile, data, { mode: 0o600 });
        execTpm('tpm2_createprimary', ['-C', 'o', '-g', 'sha256', '-G', 'rsa', '-c', primaryCtx], { tcti });
        execTpm('tpm2_pcrread', [PCR_SELECTION, '-o', pcrFile], { tcti });
        execTpm('tpm2_createpolicy', ['--policy-pcr', '-l', PCR_SELECTION, '-f', pcrFile, '-L', policyFile], { tcti });
        execTpm('tpm2_create', [
            '-C', primaryCtx,
            '-g', 'sha256',
            '-L', policyFile,
            '-u', publicFile,
            '-r', privateFile,
            '-i', inputFile,
        ], { tcti });
        execTpm('tpm2_load', ['-C', primaryCtx, '-u', publicFile, '-r', privateFile, '-c', sealedCtx], { tcti });
        tryExecTpm('tpm2_flushcontext', ['-t'], { tcti });
        tryExecTpm('tpm2_flushcontext', ['-s'], { tcti });
        return {
            version: constants_js_1.TPM_VERSION,
            sealedData: fs.readFileSync(sealedCtx),
            publicKey: fs.readFileSync(publicFile),
            algorithm: 'tpm2-policy-pcr',
            createdAt: Date.now(),
            pcrSelection: PCR_SELECTION,
        };
    }
    finally {
        try {
            fs.writeFileSync(inputFile, Buffer.alloc(data.length), { flag: 'w' });
        }
        catch {
            // Best effort wipe before directory removal.
        }
        cleanupTempDir(tmpDir);
    }
}
/**
 * Unseals TPM-sealed data.
 *
 * See `tpmSeal` for details on production TPM and mock-mode execution.
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
    if (sealedData.algorithm !== 'tpm2-policy-pcr') {
        throw new Error(`Unsupported TPM sealed data algorithm: ${sealedData.algorithm}`);
    }
    const tcti = tctiForDevice(availability.devicePath);
    const tmpDir = mkTempDir();
    const sealedCtx = path.join(tmpDir, 'sealed.ctx');
    const sessionCtx = path.join(tmpDir, 'session.ctx');
    const pcrSelection = sealedData.pcrSelection || PCR_SELECTION;
    try {
        fs.writeFileSync(sealedCtx, sealedData.sealedData, { mode: 0o600 });
        execTpm('tpm2_startauthsession', ['--policy-session', '-S', sessionCtx], { tcti });
        execTpm('tpm2_policypcr', ['-S', sessionCtx, '-l', pcrSelection], { tcti });
        const unsealed = execTpm('tpm2_unseal', ['-c', sealedCtx, '-p', `session:${sessionCtx}`], { tcti });
        tryExecTpm('tpm2_flushcontext', [sessionCtx], { tcti });
        if (unsealed.length !== 32) {
            throw new Error(`TPM unsealed data has invalid length: ${unsealed.length}`);
        }
        return Buffer.from(unsealed);
    }
    finally {
        cleanupTempDir(tmpDir);
    }
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
        pcrSelection: sealed.pcrSelection,
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
        pcrSelection: data.pcrSelection,
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