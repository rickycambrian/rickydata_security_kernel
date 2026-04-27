# Security Model

This document describes the cryptographic protocols and trust boundaries implemented by `@rickydata/security-kernel`.

---

## Sign-to-Derive Protocol

Sign-to-Derive enables **user-controlled encryption** where the server operator cannot read user data, even with full database access.

### How It Works

1. **User signs a deterministic message** with their Ethereum wallet (MetaMask, WalletConnect, etc.).
2. The **signature is hashed** to produce a 32-byte AES-256-GCM encryption key.
3. The key is used to **encrypt user secrets** (API keys, credentials, etc.).
4. The server stores **only the encrypted ciphertext** — never the key.

### Signing Message Format

The signing message is **deterministic** — it contains no nonce, timestamp, or random value. This is critical: the same wallet signing the same message always produces the same signature, which derives the same key, which can decrypt the data.

```
Sign this message to encrypt your [secrets/API key] on [Gateway Name].

Wallet: {walletAddress}
Purpose: derive-encryption-key
```

> **Why no nonce?** A nonce or timestamp would make each signature unique, meaning the derived key changes every time. The user would lose access to previously encrypted data. Determinism is a deliberate design choice, not an oversight.

### Key Derivation

```
Ethereum signature (65 bytes) = r (32) || s (32) || v (1)
Derived key = SHA-256(r || s || v) → 32 bytes → AES-256-GCM key
```

- Same signature always produces the same key (deterministic).
- Different wallets produce different signatures for the same message, yielding different keys.
- The derived key exists only in memory during the encrypt/decrypt operation.

### What the Server Sees vs. Cannot See

| Data | Server Access |
|------|---------------|
| Wallet address | Visible (used for identity) |
| Encrypted ciphertext | Visible (stored in vault) |
| IV and auth tag | Visible (stored alongside ciphertext) |
| Signature | Briefly visible during derivation, then discarded |
| **Derived encryption key** | **Never stored — exists only in memory** |
| **Plaintext secrets** | **Never visible to server** |

Even the platform operator, with full database and disk access, cannot decrypt user data. The key exists only when the user actively signs and the derivation runs in memory. After the operation completes, the key is wiped.

### Limitations

- **Wallet compromise = data compromise.** If an attacker controls the wallet private key, they can reproduce the signature and derive the same key.
- **No key rotation without re-encryption.** Changing the derived key requires the user to decrypt all data with the old key and re-encrypt with the new one.
- **JavaScript string immutability.** While `secureWipe()` zeroes Buffer contents, decrypted strings may persist in V8 heap memory until garbage collected. For maximum security, work with Buffers directly.

---

## TEE Attestation (AMD SEV-SNP)

The production gateways run inside **AMD SEV-SNP Confidential VMs**, providing hardware-enforced memory encryption and attestation.

### What TEE Provides

- **Memory encryption**: VM memory is encrypted with a per-VM key managed by the AMD Secure Processor. The hypervisor and host OS cannot read guest memory.
- **Code integrity**: An attestation report binds the VM's launch measurement to AMD's VCEK certificate chain, proving the code running inside the VM has not been tampered with.
- **PCR-bound key sealing**: The vTPM seals encryption keys to the platform's PCR (Platform Configuration Register) state. Keys can only be unsealed on the same platform with the same measured boot state.

### Attestation Chain

```
AMD Root CA
  └── AMD SEV Signing Key
        └── VCEK (Versioned Chip Endorsement Key) — unique per CPU + firmware
              └── Attestation Report — signed by VCEK
                    └── Launch measurement — hash of VM initial state
                          └── Code hash — SHA-256 of application dist/*.js at startup
```

### Verification Endpoints

These endpoints are available on the production gateways for independent verification:

| Endpoint | Purpose |
|----------|---------|
| `GET /api/verify` | Full attestation verification — returns TEE status, code hash match, VCEK validation |
| `GET /api/attestation/report` | Raw SNP attestation report with VCEK certificate chain |
| `GET /api/attestation/build-info` | Code hash (SHA-256 of `dist/*.js`), build timestamp, git commit |

### Step-by-Step Verification

**1. Check the code hash:**

```bash
curl -s https://mcp.rickydata.org/api/attestation/build-info | jq '{codeHash, gitCommit, buildTime}'
```

Compare the `codeHash` against a local build of the same git commit to confirm the deployed code matches the public source.

**2. Verify TEE attestation:**

```bash
curl -s https://mcp.rickydata.org/api/verify | jq '{teeEnabled, codeHashMatch, vcekValid, snpReport}'
```

- `teeEnabled: true` — VM is running in SEV-SNP mode
- `codeHashMatch: true` — runtime code matches the hash sealed at boot
- `vcekValid: true` — VCEK certificate chain validates back to AMD root

**3. Inspect the VCEK certificate:**

```bash
curl -s https://mcp.rickydata.org/api/attestation/report | jq '.vcek'
```

The VCEK can be independently verified against AMD's KDS (Key Distribution Service) to confirm it was issued for the specific CPU and firmware version.

**4. Audit the source code:**

The security kernel source is available at: [github.com/rickycambrian/rickydata_security_kernel](https://github.com/rickycambrian/rickydata_security_kernel)

---

## TPM Sealing

The kernel includes TPM-based key sealing for protecting the master encryption key at rest.

### Production vs. Test Modes

- **Production**: Uses the Linux TPM 2.0 interface (`/dev/tpm0` or `/dev/tpmrm0`) and `tpm2-tools` with PCR-bound sealing. Keys are bound to the platform's measured boot state and cannot be unsealed on a different machine or incompatible PCR state.
- **Fail closed**: If the TPM device or required TPM2 commands are unavailable, production seal/unseal throws. There is no software sealing fallback in the production path.
- **Mock mode**: For unit tests, `enableTpmMock()` provides deterministic in-memory seal/unseal without any device dependency.

---

## Encryption Primitives

| Primitive | Algorithm | Key Size | Notes |
|-----------|-----------|----------|-------|
| Symmetric encryption | AES-256-GCM | 256-bit | Authenticated encryption with random IV |
| Key derivation (sign-to-derive) | SHA-256 | 256-bit | Deterministic from Ethereum signature |
| Key derivation (master key) | HKDF-SHA256 | 256-bit | Per-wallet keys from master key |
| TPM sealing | TPM2 sealed object with policy PCR | 256-bit secret input | Hardware-bound in production |
| IV generation | `crypto.randomBytes` | 96-bit | Fresh random IV per encryption |
| Auth tag | GCM built-in | 128-bit | Integrity and authenticity verification |

---

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public GitHub issue.
2. Email security concerns to the repository maintainer (see GitHub profile).
3. Include steps to reproduce, impact assessment, and any suggested fix.

We aim to acknowledge reports within 48 hours and provide a fix timeline within 7 days.
