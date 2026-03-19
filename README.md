# @rickycambrian/security-kernel

<p align="center">
  <img src="https://img.shields.io/badge/license-Source--Available-red?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/npm/v/@rickycambrian/security-kernel?style=for-the-badge" alt="npm version">
  <img src="https://img.shields.io/github/last-commit/rickycambrian/rickydata_security_kernel?style=for-the-badge" alt="Last commit">
</p>

A publicly auditable security kernel providing cryptographic primitives for user-controlled encryption. This package enables **zero-knowledge architecture** where even the operator cannot access user secrets.

> **This is NOT permissive open source.** See [LICENSE](./LICENSE) for usage terms.

---

## Table of Contents

1. [Why This Matters](#why-this-matters)
2. [Security Guarantees](#security-guarantees)
3. [How It Works](#how-it-works)
4. [Verification](#verification)
5. [Architecture](#architecture)
6. [API Reference](#api-reference)
7. [License](#license)

---

## Why This Matters

### The Problem

Traditional SaaS platforms store user secrets (API keys, credentials) in ways that the **operator can access**. Even with encryption at rest:

- The operator holds the encryption keys
- Insider threats or legal requests can expose secrets
- Users must trust the operator's security claims

### Our Solution

**Sign-to-Derive** architecture gives users cryptographic control over their secrets:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SIGN-TO-DERIVE PROTOCOL                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. USER SIGNS ENCRYPTION CHALLENGE                                │
│     ┌──────────────┐      ┌──────────────┐                          │
│     │ User Wallet  │ ───► │ Signature    │                          │
│     │ (keys held   │      │ r, s, v      │                          │
│     │  by user)    │      └──────────────┘                          │
│     └──────────────┘           │                                      │
│                                ▼                                      │
│  2. SERVER NEVER SEES KEY                                           │
│     ┌──────────────┐      ┌──────────────┐                          │
│     │ Keccak256(sig)     │ 32-byte Key   │  ◄── Server only        │
│     │     │         │ ──► │ (derived,     │       sees signature    │
│     │     │         │      │  never stored)                         │
│     └──────────────┘      └──────────────┘                          │
│                                │                                      │
│                                ▼                                      │
│  3. USER DATA IS ENCRYPTED                                          │
│     ┌──────────────┐      ┌──────────────┐                          │
│     │ AES-256-GCM  │      │ Encrypted    │                          │
│     │ (user key)   │ ───► │ data stored  │                          │
│     └──────────────┘      │ on server    │                          │
│                          └──────────────┘                          │
│                                                                     │
│  RESULT: Server can encrypt/decrypt ONLY when user provides         │
│          a fresh signature. Without it, secrets are forever         │
│          inaccessible.                                             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Security Guarantees

### What We Cannot Do (Even If We Wanted To)

| Capability | With Sign-to-Derive | Without |
|------------|---------------------|---------|
| Read user's API keys | ❌ Impossible | ✅ Possible with key |
| Read user's encrypted data | ❌ Impossible | ✅ Possible with key |
| Decrypt past sessions | ❌ Impossible | ✅ Possible with key |
| Extract secrets from disk | ❌ Impossible | ✅ Possible with key |
| Respond to legal requests | ❌ Cannot | ✅ Could be compelled |

### What We CAN Do

- **Encrypt** data when user provides a signature
- **Verify** signatures are valid (but never derive the key)
- **Store** encrypted blobs that we cannot decrypt
- **Delete** user data on request

---

## How It Works

### 1. Encryption Layer (AES-256-GCM)

```typescript
import { encrypt, decrypt } from '@rickycambrian/security-kernel';

const key = crypto.randomBytes(32);
const { encrypted, iv, authTag } = encrypt('my secret', key);
const decrypted = decrypt(encrypted, iv, authTag, key);
```

- **AES-256-GCM**: Industry-standard authenticated encryption
- **12-byte IV**: Prevents pattern analysis
- **16-byte Auth Tag**: Detects tampering

### 2. Sign-to-Derive Key Derivation

```typescript
import { deriveKeyFromSignature, encryptWithSignature, decryptWithSignature } from '@rickycambrian/security-kernel';

// User signs with their wallet
const signature = await wallet.signMessage('Encrypt my data');

// Server encrypts - but never sees the key!
const encrypted = encryptWithSignature('my-api-key', signature);

// User decrypts with same signature
const decrypted = decryptWithSignature(encrypted, signature);
```

The magic: `keccak256(signature) → 32-byte key`

- The server receives the signature, not the key
- Every signature produces a unique key
- Without the signature, the data is cryptographically inaccessible

### 3. TPM-Backed Master Key

For non-sign-to-derive encryption (system-level secrets):

```typescript
import { initMasterKey, sealMasterKey, unsealMasterKey } from '@rickycambrian/security-kernel';

// Production: TPM must be available (container FAILS if unavailable)
initMasterKey({
  sealedKeyPath: '/var/lib/agent-gateway/secrets/master-key.sealed',
  allowFallback: false  // Required: TPM for production
});

// Master key is sealed to TPM hardware
sealMasterKey(masterKey, storagePath);

// On restart: TPM unseals the master key
const key = unsealMasterKey(storagePath);
```

- **TPM 2.0**: Hardware-backed key protection
- **PCR Binding**: Key only unseals if boot state matches
- **No Key in Memory**: Master key loaded only when needed

---

## Verification

### Option 1: Security Dashboard

Visit **[https://mcpmarketplace.rickydata.org/security](https://mcpmarketplace.rickydata.org/security)**

This page provides:
- **TEE Attestation Report**: Cryptographic proof that code runs in AMD SEV-SNP
- **Security Kernel Code Hash**: SHA-256 of this package's source
- **Live Status**: Current trust state, PCR measurements, key status

### Option 2: Verify the Code Yourself

1. **Inspect this repository**:
   ```bash
   git clone https://github.com/rickycambrian/rickydata_security_kernel.git
   cd rickydata_security_kernel
   ```

2. **Review the implementation**:
   - `src/encryption.ts`: AES-256-GCM implementation
   - `src/sign-to-derive.ts`: Key derivation from signatures
   - `src/tpm-sealer.ts`: TPM sealing with PCR binding

3. **Compute the code hash**:
   ```bash
   npm install
   npm run build
   # Hash the dist/ folder contents
   ```

4. **Compare with attestation**:
   - The attestation quote includes this hash
   - Match = code hasn't been tampered with

### Option 3: Verify TEE Attestation

```bash
# Fetch attestation from Agent Gateway
curl -s https://agents.rickydata.org/health | jq '.securityPosture'

# This returns:
# {
#   "tee": "SEV-SNP",
#   "attestation": "verified",
#   "codeHash": "sha256:...",
#   "pcrs": { "0": "...", "1": "...", ... }
# }
```

Compare the `codeHash` with the hash of this package.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    RICKYDATA PLATFORM                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────────────────────┐  │
│  │   Your Browser  │    │       Agent Gateway (TEE)        │  │
│  │                 │    │  ┌─────────────────────────────┐  │  │
│  │ ┌─────────────┐ │    │ │   Security Kernel (this)  │  │  │
│  │ │ Wallet       │ │───►│ │                             │  │  │
│  │ │ (keys local) │ │    │ │ • AES-256-GCM encryption   │  │  │
│  │ └─────────────┘ │    │ │ • Sign-to-derive (S2D)      │  │  │
│  │                 │    │ │ • TPM sealing/unsealing      │  │  │
│  │ ┌─────────────┐ │    │ │ • Secure wipe primitives    │  │  │
│  │ │ Signature   │ │───►│ │                             │  │  │
│  │ │ (sent only) │ │    │ └─────────────────────────────┘  │  │
│  │ └─────────────┘ │    │              │                    │  │
│  │                 │    │              ▼                    │  │
│  │ ┌─────────────┐ │    │   ┌───────────────────────┐     │  │
│  │ │ Encrypted   │◄────│───│─ │ TPM 2.0 (hardware)   │     │  │
│  │ │ Data        │ │    │   │ • PCR-bound sealing   │     │  │
│  │ └─────────────┘ │    │   │ • Key never exported  │     │  │
│  └─────────────────┘    │   └───────────────────────┘     │  │
│                         └─────────────────────────────────┘  │
│                                        │                        │
│                                        ▼                        │
│                         ┌─────────────────────────────────┐   │
│                         │    AMD SEV-SNP Confidential     │   │
│                         │    VM (attestation verified)    │   │
│                         └─────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Defense Layers

| Layer | Protection |
|-------|------------|
| **Sign-to-Derive** | Operator cannot derive encryption keys |
| **TPM Sealing** | Master key requires hardware to unseal |
| **SEV-SNP TEE** | Code runs in confidential VM |
| **Attestation** | Cryptographic proof of what code runs |
| **Secure Wipe** | Keys cleared from memory after use |

---

## API Reference

### Encryption

```typescript
import { encrypt, decrypt, secureWipe } from '@rickycambrian/security-kernel';

// Encrypt
const result = encrypt(plaintext: string, key: Buffer): EncryptedData
// Returns: { encrypted: Buffer, iv: Buffer, authTag: Buffer }

// Decrypt
const plaintext = decrypt(encrypted: Buffer, iv: Buffer, authTag: Buffer, key: Buffer): string

// Secure wipe (always call after working with sensitive data!)
secureWipe(buffer: Buffer): void
```

### Sign-to-Derive

```typescript
import { deriveKeyFromSignature, encryptWithSignature, decryptWithSignature } from '@rickycambrian/security-kernel';

// Derive key from Ethereum signature
const key = deriveKeyFromSignature(signature: string): Buffer

// Encrypt with signature-derived key
const result = encryptWithSignature(plaintext: string, signature: string): SignToDeriveResult
// Returns: { encrypted: string, iv: string, authTag: string } (base64 encoded)

// Decrypt with signature
const plaintext = decryptWithSignature(
  encryptedBase64: string,
  ivBase64: string,
  authTagBase64: string,
  signature: string
): string
```

### TPM Sealing

```typescript
import { checkTpmAvailability, tpmSeal, tpmUnseal, sealMasterKey, unsealMasterKey } from '@rickycambrian/security-kernel';

// Check TPM availability
const status = checkTpmAvailability(): TpmAvailability
// Returns: { available: boolean, reason?: string, devicePath?: string }

// Seal data to TPM
const sealed = tpmSeal(data: Buffer): TpmSealedData

// Unseal TPM data
const data = tpmUnseal(sealedData: TpmSealedData): Buffer

// Persist sealed master key
sealMasterKey(masterKey: Buffer, storagePath: string): void
const key = unsealMasterKey(storagePath: string): Buffer

// Check if sealed key exists
const exists = hasSealedMasterKey(storagePath: string): boolean
```

### Testing

```typescript
import { enableTpmMock, disableTpmMock } from '@rickycambrian/security-kernel';

// Enable TPM mock for testing (no hardware required)
enableTpmMock(seedData: Buffer): void

// Disable mock and use real TPM
disableTpmMock(): void
```

---

## Installation

```bash
npm install @rickycambrian/security-kernel
```

### Requirements

- Node.js 18+
- TypeScript 5.3+ (if using TypeScript)
- TPM 2.0 (for production use; mock available for testing)

---

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Build
npm run build
```

---

## Security Considerations

### For Users

1. **Your wallet holds the keys**: Never share your private keys
2. **Signatures are scoped**: Each signature can only encrypt/decrypt data
3. **Session signatures**: You may need to re-sign periodically

### For Operators

1. **Always use TPM in production**: Set `allowFallback: false`
2. **Call secureWipe()**: After encrypt/decrypt operations
3. **Handle key rotation**: Use persistent store with multiple keys

---

## License

**This is NOT open source software.**

This software is provided under a Source-Available license. See [LICENSE](./LICENSE) for:

- ✅ What you CAN do (audit, verify, use with Rickydata services)
- ❌ What you CANNOT do (fork, build competing products, redistribute)

---

## Related Links

- **Security Dashboard**: [https://mcpmarketplace.rickydata.org/security](https://mcpmarketplace.rickydata.org/security)
- **Agent Gateway**: [https://agents.rickydata.org](https://agents.rickydata.org)
- **MCP Gateway**: [https://mcp.rickydata.org](https://mcp.rickydata.org)
- **TEE Attestation**: [https://agents.rickydata.org/health](https://agents.rickydata.org/health)

---

## Questions?

- **Security Issues**: security@rickydata.org
- **General Inquiries**: contact@rickydata.org
- **Legal**: legal@rickydata.org
