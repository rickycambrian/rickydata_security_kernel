# Security Kernel API Design Document

**Package**: `@rickycambrian/security-kernel`
**Version**: 1.0.0 (Phase 1)
**Target**: Public npm distribution
**Repository**: `/Users/riccardoesclapon/Documents/github/rickydata_security_kernel/`

---

## Executive Summary

The Security Kernel provides a portable TypeScript library for cryptographic key management, user-controlled encryption (sign-to-derive), and TPM-backed secret sealing. It extracts battle-tested security primitives from the agent gateway for use by the broader Rickydata platform and external developers.

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    @rickycambrian/security-kernel               │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │  Encryption │  │   Key       │  │      TPM Vault          │ │
│  │   Module    │  │ Derivation  │  │    (Sealing/Unsealing)  │ │
│  ├─────────────┤  ├─────────────┤  ├─────────────────────────┤ │
│  │ AES-256-GCM│  │    HKDF     │  │  TPM 2.0 / Mock         │ │
│  │  + Secure   │  │ Sign-to-    │  │  PCR-bound Sealing     │ │
│  │  Wipe       │  │ Derive      │  │  Persistent Storage    │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Core Principles

1. **Defense in Depth**: All secrets encrypted at rest and in transit
2. **Zero-Knowledge**: Sign-to-derive mode ensures server never sees encryption keys
3. **Hardware-Backed**: TPM sealing for production, software fallback for development
4. **Memory Safety**: Secure wipe primitives for all sensitive buffers
5. **Auditability**: Comprehensive metrics and decision logging

---

## 2. Phase 1 Extraction Scope

### 2.1 Included Components

| Component | Source File | Description |
|-----------|-------------|-------------|
| Encryption | `encryption.ts` | AES-256-GCM encrypt/decrypt with secure wipe |
| Key Derivation | `key-derivation.ts` | HKDF derivation + Sign-to-Derive |
| TPM Vault | `tpm-vault.ts` | TPM sealing/unsealing with persistence |
| Persistent Store | `persistent-apikey-store.ts` | Encrypted file-based storage with key rotation |
| Release Guard | `release-guard.ts` | TEE trust state enforcement (optional) |

### 2.2 Excluded (Phase 2+)

- Agent-specific vault integration (`vault.ts`, `agent-secret-vault.ts`)
- SEV-SNP attestation service integration
- OpenAI/MiniMax provider-specific vaults

---

## 3. Public API Design

### 3.1 Encryption Module

```typescript
// src/encryption/index.ts

/**
 * Encrypts a string using AES-256-GCM
 * @param plaintext - Value to encrypt
 * @param key - 32-byte encryption key
 * @returns Encrypted data with IV and auth tag
 */
export function encrypt(
  plaintext: string,
  key: Buffer
): EncryptedData;

/**
 * Decrypts AES-256-GCM encrypted data
 * @param encrypted - Ciphertext buffer
 * @param iv - Initialization vector (12 bytes)
 * @param authTag - Authentication tag (16 bytes)
 * @param key - 32-byte decryption key
 * @returns Decrypted plaintext
 */
export function decrypt(
  encrypted: Buffer,
  iv: Buffer,
  authTag: Buffer,
  key: Buffer
): string;

/**
 * Securely overwrites a buffer with zeros
 */
export function secureWipe(buffer: Buffer): void;

/**
 * Securely clears a string (creates buffer, wipes, discards)
 */
export function secureWipeString(str: string): void;

export interface EncryptedData {
  encrypted: Buffer;
  iv: Buffer;
  authTag: Buffer;
}
```

### 3.2 Key Derivation Module

```typescript
// src/key-derivation/index.ts

/**
 * Configuration for master key initialization
 */
export interface MasterKeyConfig {
  sealedKeyPath?: string;
  allowFallback?: boolean;
}

/**
 * Initializes the key derivation system
 * TPM mode: loads existing sealed key or creates new
 * Fallback mode: random key (development only)
 */
export function initMasterKey(config?: MasterKeyConfig): void;

/**
 * Derives a user-specific encryption key from master key using HKDF
 * @param walletAddress - User's Ethereum wallet (0x-prefixed)
 * @param userSalt - 32-byte per-user random salt
 * @returns 32-byte derived key
 */
export function deriveUserKey(
  walletAddress: string,
  userSalt: Buffer
): Buffer;

/**
 * Computes HMAC-SHA256 vault lookup key from wallet address
 * Use instead of plaintext wallet as Map key
 */
export function computeVaultKey(walletAddress: string): string;

/**
 * Clears master key from memory (call on shutdown)
 */
export function clearMasterKey(): void;

/**
 * Checks if master key is initialized
 */
export function isMasterKeyInitialized(): boolean;

/**
 * Derives encryption key from Ethereum signature (Sign-to-Derive)
 * @param signature - 65-byte Ethereum signature (r, s, v)
 * @returns 32-byte derived key
 */
export function deriveKeyFromSignature(signature: string): Buffer;

/**
 * Encrypts using signature-derived key
 */
export function encryptWithSignature(
  plaintext: string,
  signature: string
): { encrypted: string; iv: string; authTag: string };

/**
 * Decrypts using signature-derived key
 */
export function decryptWithSignature(
  encryptedBase64: string,
  ivBase64: string,
  authTagBase64: string,
  signature: string
): string;
```

### 3.3 TPM Vault Module

```typescript
// src/tpm-vault/index.ts

export interface TpmAvailability {
  available: boolean;
  reason?: string;
  devicePath?: string;
}

export interface TpmSealedData {
  version: number;
  sealedData: Buffer;
  publicKey: Buffer;
  algorithm: string;
  createdAt: number;
}

/**
 * Checks if TPM is available on the system
 */
export function checkTpmAvailability(): TpmAvailability;

/**
 * Enables mock mode for testing (no real TPM required)
 */
export function enableTpmMock(
  sealedData: Buffer,
  unsealFn?: (data: Buffer) => Buffer,
  publicKey?: Buffer
): void;

/**
 * Disables mock mode
 */
export function disableTpmMock(): void;

/**
 * Checks if mock mode is active
 */
export function isTpmMockEnabled(): boolean;

/**
 * Seals data using TPM (or mock in test mode)
 */
export function tpmSeal(data: Buffer): TpmSealedData;

/**
 * Unseals TPM-sealed data
 */
export function tpmUnseal(sealedData: TpmSealedData): Buffer;

/**
 * Seals master key to disk (TPM-protected)
 */
export function sealMasterKey(masterKey: Buffer, storagePath: string): void;

/**
 * Unseals and loads master key from disk
 */
export function unsealMasterKey(storagePath: Buffer): string;

/**
 * Checks if sealed master key exists
 */
export function hasSealedMasterKey(storagePath: string): boolean;

/**
 * Removes sealed master key
 */
export function removeSealedMasterKey(storagePath: string): void;
```

### 3.4 Persistent Store Module

```typescript
// src/persistent-store/index.ts

export interface PersistedApiKeyData {
  apiKey: string;
  createdAt: string;
  lastUsedAt: string;
  schemaVersion?: 1;
}

export interface PersistentStoreConfig {
  baseDir: string;
  encryptionKey: string;
  previousEncryptionKeys?: string[];
}

export interface PersistentStoreStats {
  reads: number;
  readHits: number;
  readMisses: number;
  readErrors: number;
  writes: number;
  writeErrors: number;
  deletes: number;
  deleteHits: number;
  deleteMisses: number;
  fallbackKeyCount: number;
}

export class PersistentApiKeyStore {
  constructor(config: PersistentStoreConfig);

  /**
   * Validates store is ready (directory permissions, etc.)
   */
  assertReady(): Promise<void>;

  /**
   * Read and decrypt API key (with key rotation fallback)
   */
  readApiKey(walletAddress: string): Promise<PersistedApiKeyData | null>;

  /**
   * Encrypt and write API key atomically
   */
  writeApiKey(walletAddress: string, data: PersistedApiKeyData): Promise<void>;

  /**
   * Delete API key and directory
   */
  deleteApiKey(walletAddress: string): Promise<boolean>;

  /**
   * Check if API key exists (without decrypting)
   */
  hasApiKey(walletAddress: string): Promise<boolean>;

  /**
   * List all wallet HMAC directories
   */
  listWallets(): Promise<string[]>;

  /**
   * Get runtime statistics
   */
  getStats(): PersistentStoreStats;

  // --- Sign-to-Derive Methods ---

  /**
   * Write using user-controlled encryption
   */
  writeApiKeyWithSignature(
    walletAddress: string,
    data: PersistedApiKeyData,
    signature: string
  ): Promise<void>;

  /**
   * Read using signature-derived key
   */
  readApiKeyWithSignature(
    walletAddress: string,
    signature: string
  ): Promise<PersistedApiKeyData | null>;

  /**
   * Delete sign-to-derive key
   */
  deleteApiKeyWithSignature(walletAddress: string): Promise<boolean>;
}
```

### 3.5 Release Guard (Optional Integration)

```typescript
// src/release-guard/index.ts

export type SecretReleaseTrustState = 'trusted' | 'degraded' | 'unavailable';
export type SecretReleaseGuardMode = 'permissive' | 'audit' | 'enforced';

export interface SecretReleaseDecision {
  allowed: boolean;
  wouldBlockIfFailClosed: boolean;
  state: SecretReleaseTrustState;
  reasonCode: string;
  detail: string | null;
}

export interface SecretReleaseGuardMetrics {
  mode: SecretReleaseGuardMode;
  decisionsTotal: number;
  trustedCount: number;
  degradedCount: number;
  unavailableCount: number;
  guardErrorCount: number;
  lastDecisionAt: string | null;
}

export interface SecretReleaseTrustSnapshot {
  state: SecretReleaseTrustState;
  reasonCode?: string;
  detail?: string | null;
}

export type SecretReleaseTrustProvider = () => SecretReleaseTrustSnapshot | Promise<SecretReleaseTrustSnapshot>;

/**
 * Set custom trust state provider (for TEE integration)
 */
export function setSecretReleaseTrustProvider(provider: SecretReleaseTrustProvider): void;

/**
 * Get current metrics
 */
export function getSecretReleaseGuardMetrics(): SecretReleaseGuardMetrics;

/**
 * Observe release decision (call before releasing secrets)
 */
export function observeRelease(context: {
  walletAddress: string;
  source: string;
}): Promise<SecretReleaseDecision>;

/**
 * Reset for testing
 */
export function resetReleaseGuardForTests(): void;
```

---

## 4. Usage Patterns

### 4.1 Basic Encryption

```typescript
import { encrypt, decrypt, secureWipe } from '@rickycambrian/security-kernel/encryption';

const key = crypto.randomBytes(32);
const { encrypted, iv, authTag } = encrypt('secret value', key);

const decrypted = decrypt(encrypted, iv, authTag, key);
console.log(decrypted); // 'secret value'

secureWipe(key);
```

### 4.2 User-Controlled Encryption (Sign-to-Derive)

```typescript
import {
  encryptWithSignature,
  decryptWithSignature
} from '@rickycambrian/security-kernel/key-derivation';

// User signs a message with their wallet
const signature = await wallet.signMessage('Encrypt my data');

// Server encrypts (never sees the key)
const { encrypted, iv, authTag } = encryptWithSignature(
  'my-api-key',
  signature
);

// User decrypts with same signature
const decrypted = decryptWithSignature(
  encrypted,
  iv,
  authTag,
  signature
);
```

### 4.3 TPM-Backed Master Key

```typescript
import {
  initMasterKey,
  clearMasterKey,
  sealMasterKey,
  unsealMasterKey,
  hasSealedMasterKey
} from '@rickycambrian/security-kernel/key-derivation';

// Initialize (TPM required in production)
initMasterKey({
  sealedKeyPath: '/var/lib/myapp/secrets/master-key.sealed',
  allowFallback: process.env.NODE_ENV === 'development'
});

// Later: check if sealed key exists
if (hasSealedMasterKey('/var/lib/myapp/secrets/master-key.sealed')) {
  const key = unsealMasterKey('/var/lib/myapp/secrets/master-key.sealed');
  // Use key...
}

// On shutdown
clearMasterKey();
```

### 4.4 Persistent Storage with Key Rotation

```typescript
import { PersistentApiKeyStore } from '@rickycambrian/security-kernel/persistent-store';

const store = new PersistentApiKeyStore({
  baseDir: '/var/lib/myapp/vault',
  encryptionKey: process.env.VAULT_ENCRYPTION_KEY!,
  previousEncryptionKeys: [
    process.env.OLD_VAULT_KEY_1!,
    process.env.OLD_VAULT_KEY_2!,
  ]
});

await store.assertReady();

// Store
await store.writeApiKey(walletAddress, {
  apiKey: 'sk-ant-...',
  createdAt: new Date().toISOString(),
  lastUsedAt: new Date().toISOString()
});

// Read (auto-rotates if using old key)
const data = await store.readApiKey(walletAddress);

// Check existence
const exists = await store.hasApiKey(walletAddress);

// Get stats
const stats = store.getStats();
```

---

## 5. Type Exports

### 5.1 Main Export Barrel

```typescript
// src/index.ts

// Encryption
export {
  encrypt,
  decrypt,
  secureWipe,
  secureWipeString
} from './encryption';

export type { EncryptedData } from './encryption';

// Key Derivation
export {
  initMasterKey,
  deriveUserKey,
  computeVaultKey,
  clearMasterKey,
  isMasterKeyInitialized,
  deriveKeyFromSignature,
  encryptWithSignature,
  decryptWithSignature
} from './key-derivation';

export type { MasterKeyConfig } from './key-derivation';

// TPM Vault
export {
  checkTpmAvailability,
  enableTpmMock,
  disableTpmMock,
  isTpmMockEnabled,
  tpmSeal,
  tpmUnseal,
  sealMasterKey,
  unsealMasterKey,
  hasSealedMasterKey,
  removeSealedMasterKey
} from './tpm-vault';

export type { TpmAvailability, TpmSealedData } from './tpm-vault';

// Persistent Store
export { PersistentApiKeyStore } from './persistent-store';

export type {
  PersistedApiKeyData,
  PersistentStoreConfig,
  PersistentStoreStats
} from './persistent-store';

// Release Guard (optional)
export {
  setSecretReleaseTrustProvider,
  getSecretReleaseGuardMetrics,
  observeRelease,
  resetReleaseGuardForTests
} from './release-guard';

export type {
  SecretReleaseTrustState,
  SecretReleaseGuardMode,
  SecretReleaseDecision,
  SecretReleaseGuardMetrics,
  SecretReleaseTrustSnapshot,
  SecretReleaseTrustProvider
} from './release-guard';
```

---

## 6. Implementation Notes

### 6.1 Directory Structure

```
rickydata_security_kernel/
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── src/
│   ├── index.ts                    # Main exports
│   ├── encryption/
│   │   ├── index.ts
│   │   ├── encryption.ts           # Core AES-256-GCM
│   │   └── encryption.test.ts
│   ├── key-derivation/
│   │   ├── index.ts
│   │   ├── key-derivation.ts      # HKDF + Sign-to-Derive
│   │   └── key-derivation.test.ts
│   ├── tpm-vault/
│   │   ├── index.ts
│   │   ├── tpm-vault.ts           # TPM sealing
│   │   └── tpm-vault.test.ts
│   ├── persistent-store/
│   │   ├── index.ts
│   │   ├── persistent-apikey-store.ts
│   │   └── persistent-apikey-store.test.ts
│   └── release-guard/
│       ├── index.ts
│       ├── release-guard.ts
│       └── release-guard.test.ts
├── README.md
└── LICENSE
```

### 6.2 Dependencies

```json
{
  "name": "@rickycambrian/security-kernel",
  "version": "1.0.0",
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "types": "./dist/index.d.ts"
    },
    "./encryption": {
      "import": "./dist/encryption/index.js",
      "types": "./dist/encryption/index.d.ts"
    },
    "./key-derivation": {
      "import": "./dist/key-derivation/index.js",
      "types": "./dist/key-derivation/index.d.ts"
    },
    "./tpm-vault": {
      "import": "./dist/tpm-vault/index.js",
      "types": "./dist/tpm-vault/index.d.ts"
    },
    "./persistent-store": {
      "import": "./dist/persistent-store/index.js",
      "types": "./dist/persistent-store/index.d.ts"
    },
    "./release-guard": {
      "import": "./dist/release-guard/index.js",
      "types": "./release-guard/index.d.ts"
    }
  },
  "scripts": {
    "build": "tsc",
    "test": "vitest run",
    "test:watch": "vitest"
  },
  "devDependencies": {
    "typescript": "^5.3.0",
    "vitest": "^1.2.0",
    "@types/node": "^20.10.0"
  }
}
```

### 6.3 Security Considerations

1. **No Default Exports**: Named exports prevent accidental misuse
2. **Buffer Over String**: Prefer Buffer types for sensitive data
3. **Secure Wipe Required**: Document that users must call `secureWipe` after use
4. **Key Rotation**: Persistent store supports multiple encryption keys
5. **Mock for Tests**: TPM mock enables CI without hardware

---

## 7. Migration Guide for Agent Gateway

After package publication:

```typescript
// Before (direct import)
import { encrypt } from '../secrets/encryption.js';

// After (package import)
import { encrypt } from '@rickycambrian/security-kernel/encryption';
```

### Environment Variable Mapping

| Agent Gateway Env | Security Kernel |
|-------------------|-----------------|
| `TPM_SEALED_KEY_PATH` | Pass via `MasterKeyConfig.sealedKeyPath` |
| `ALLOW_MASTER_KEY_FALLBACK` | Pass via `MasterKeyConfig.allowFallback` |
| `NODE_ENV=test` | Auto-enables mock in tests |

---

## 8. Phase 2 Considerations

Future phases may include:

1. **Software-only Vault**: For non-TEE environments
2. **Key Ceremony Support**: Multi-party key generation
3. **HSM Integration**: Hardware Security Module abstraction
4. **Audit Logging**: Structured audit trail for compliance
5. **Key Escrow**: Recovery mechanisms for lost keys

---

## 9. Testing Strategy

### Unit Tests (Phase 1)

- All encryption/decryption round-trips
- Key derivation determinism
- TPM mock behavior
- Persistent store atomicity
- Key rotation scenarios

### Integration Tests (Phase 2)

- Real TPM hardware (if available in CI)
- Multi-process concurrent writes
- Disk persistence after process restart

---

## 10. Acceptance Criteria

- [ ] All source files compile without errors
- [ ] All tests pass (`npm test`)
- [ ] TypeScript declarations generated correctly
- [ ] Package publishes to npm
- [ ] Agent gateway integration tests pass
- [ ] Documentation examples work
