# @rickydata/security-kernel Trust Chain

## Overview

This document describes how `@rickydata/security-kernel` provides the cryptographic foundation for both the MCP Gateway and Agent Gateway TEEs, enabling public auditability of the exact same security code in both systems.

## Trust Chain

```
┌─────────────────────────────────────────────────────────────────┐
│                    TRUST CHAIN                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. SECURITY KERNEL (@rickydata/security-kernel)           │
│     ├─ AES-256-GCM encryption                                │
│     ├─ HKDF key derivation (in-memory or TPM-sealed)         │
│     ├─ Sign-to-derive (operator cannot read user data)       │
│     └─ TPM sealing with PCR binding                          │
│                           │                                      │
│                           ▼                                      │
│  2. MCP GATEWAY TEE (mcp-gateway)                        │
│     ├─ AMD SEV-SNP confidential VM                          │
│     ├─ In-memory encryption (fresh random key each startup)  │
│     └─ Attestation verified at /health                       │
│                           │                                      │
│                           ▼                                      │
│  3. AGENT GATEWAY TEE (mcp-agent-gateway)                │
│     ├─ AMD SEV-SNP confidential VM                          │
│     ├─ TPM-sealed keys with PCR binding                     │
│     ├─ Attestation verified at /health                       │
│     └─ BYOK Anthropic API key management                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Dual Encryption Models

The security kernel supports two encryption models:

| Model | Used By | Key Source | Persistence |
|-------|---------|-------------|-------------|
| **In-Memory** | MCP Gateway | Fresh 32-byte random key each startup | None (restart = clean slate) |
| **TPM-Sealed** | Agent Gateway | PCR-bound TPM key | Survives restarts via TPM unsealing |

Both models use the same AES-256-GCM encryption and HKDF key derivation code, just with different master key sources.

## Verification Commands

### 1. Check Security Kernel npm Package
```bash
npm view @rickydata/security-kernel version
npm view @rickydata/security-kernel license
```

### 2. Verify MCP Gateway TEE
```bash
curl -s https://mcp.rickydata.org/health | jq '.securityPosture'
# Returns: { tee: "SEV-SNP", attestation: "verified", keySources: {...} }
```

### 3. Verify Agent Gateway TEE
```bash
curl -s https://agents.rickydata.org/health | jq '.securityPosture'
# Returns: { tee: "SEV-SNP", attestation: "verified", keySources: {...} }
```

### 4. Verify MCP Gateway Uses In-Memory Security Kernel
```bash
curl -s https://mcp.rickydata.org/health | jq '.securityPosture.keySources'
# Expected: vaultEncryptionKey uses "gateway_secret_key_fallback"
```

### 5. Verify Agent Gateway Uses TPM-Sealed Security Kernel
```bash
curl -s https://agents.rickydata.org/health | jq '.securityPosture.keySources'
# Expected: ALL keys show "tpm_pcr", including byokVaultEncryptionKey
# If byokVaultEncryptionKey shows "env_fallback", the operator could read user secrets
```

### 6. Verify BYOK Vault Key Is Zero-Knowledge
```bash
# Confirm the BYOK vault key source is tpm_pcr (NOT env_fallback)
curl -s https://agents.rickydata.org/health | jq '.securityPosture.keySources.byokVaultEncryptionKey'
# Must return: "tpm_pcr"
# This key encrypts user API keys at rest. When TPM-bound, the operator cannot extract it.
# The key is randomly generated on the VM and sealed to TPM — it never exists in GitHub secrets.
```

### 7. Public Audit - Verify Security Kernel Source Code
```bash
# View the public npm package source
npm view @rickydata/security-kernel repository.url

# Or clone and verify
git clone https://github.com/rickycambrian/rickydata_security_kernel.git
cd rickydata_security_kernel
npm run build
npm test
```

## Security Guarantees

With this trust chain:

| Capability | Guarantee |
|------------|------------|
| Read user API keys | ❌ Impossible (Sign-to-derive or per-wallet derived keys) |
| Read encrypted data | ❌ Impossible (key derived from wallet signature or random) |
| Extract secrets from disk | ❌ Impossible (TPM-sealed or in-memory only) |
| Recover user secrets after TPM reset | ❌ Impossible (BYOK vault key is randomly generated and sealed — never in GitHub secrets) |
| Operator reads BYOK vault key | ❌ Impossible (never falls back to operator-accessible `LEDGER_ENCRYPTION_KEY`) |
| Modify security kernel | ❌ Impossible (attestation detects code changes) |
| Fake attestation | ❌ Impossible (hardware-rooted AMD SEV-SNP) |

## Architecture Details

### MCP Gateway (In-Memory Model)
- **Master Key**: Fresh 32-byte random value generated at startup
- **Per-User Keys**: HKDF-derived using wallet address + per-user random salt
- **Per-Server Keys**: HKDF with serverId in info parameter for isolation
- **Vault Lookup**: HMAC-SHA256 of wallet address (no plaintext stored)
- **Restart Behavior**: All secrets cleared on restart (by design)

### Agent Gateway (TPM-Sealed Model)
- **Master Key**: Sealed in TPM with PCR policy (sha256:0,1,2,3,4,5,7)
- **Per-User Keys**: HKDF-derived from unsealed master key
- **BYOK Vault Key**: Randomly generated on VM and sealed to TPM. Never stored in GitHub secrets. If TPM reset occurs, a fresh key is generated (old user secrets are unrecoverable by design — zero-knowledge preserved).
- **Recovery**: Automatic unsealing on restart if TPM state unchanged. Deploy auto-heals vTPM slot exhaustion via `tpm2_clear`.
- **Fallback**: Infrastructure keys (JWT, ledger) use env vars if TPM unavailable. BYOK vault key **never** falls back to an operator-readable key.

## Files

- **Agent Gateway Source**: `mcp-agent-gateway/src/secrets/` (TPM model)
- **MCP Gateway Source**: `mcp-gateway/src/secrets/` (in-memory model)
- **Security Kernel Package**: `rickydata_security_kernel/`
- **npm Distribution**: `@rickydata/security-kernel`

## Sync Workflow

The security kernel is synced from both gateways to the npm package:

1. Agent Gateway security files → TPM-sealed model in security-kernel
2. MCP Gateway security files → In-memory model in security-kernel
3. Both models published together in `@rickydata/security-kernel`

This ensures public auditability of the exact same crypto code running in both TEEs.