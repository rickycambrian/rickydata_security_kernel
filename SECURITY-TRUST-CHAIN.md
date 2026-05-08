# @rickydata/security-kernel Trust Chain

## Overview

This document describes how `@rickydata/security-kernel` provides the public audit surface for the cryptographic primitives used by the MCP Gateway, Agent Gateway, and KFDB TEE services. Production attestation proves the private runtime images currently running; this package proves the source-available encryption, key-derivation, and TPM-sealing primitives reviewers can inspect.

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
│     ├─ Rust trust plane for sandbox/secret/proof boundaries  │
│     └─ Attestation verified at /health + /api/attestation    │
│                           │                                      │
│                           ▼                                      │
│  3. AGENT GATEWAY TEE (mcp-agent-gateway)                │
│     ├─ AMD SEV-SNP confidential VM                          │
│     ├─ TPM-sealed keys with PCR binding                     │
│     ├─ Attestation verified at /health                       │
│     └─ BYOK Anthropic API key management                     │
│                           │                                      │
│                           ▼                                      │
│  4. KFDB API TEE (knowledgeflow_db)                    │
│     ├─ AMD SEV-SNP confidential VM                          │
│     ├─ TPM PCR-bound master key                             │
│     ├─ Enforced release guard for data release paths         │
│     └─ Public evidence bundle under evidence/latest.json     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Dual Encryption Models

The security kernel supports two encryption models:

| Model | Used By | Key Source | Persistence |
|-------|---------|-------------|-------------|
| **In-Memory** | MCP Gateway | Fresh 32-byte random key each startup | None (restart = clean slate) |
| **TPM-Sealed** | Agent Gateway | PCR-bound TPM key | Survives restarts via TPM unsealing |

Both models use AES-256-GCM encryption and HKDF-style key separation, with different master key sources.

## Rust Trust Plane Boundary

`@rickydata/security-kernel` is the public audit surface for cryptography. The MCP Gateway also ships Rust trust-plane helpers inside the production image for the hard runtime boundary:

| Helper | Runtime responsibility | Public proof |
|--------|------------------------|--------------|
| `sandboxd` | Container planning/start policy, network posture, per-session isolation | `.trustPlane.binaries.sandboxd.sha256` in MCP provenance |
| `trust-plane` | Secret-release decisions and proof/receipt canonicalization | `.trustPlane.binaries.trustPlane.sha256` in MCP provenance |

This repository does not contain those Rust helpers. They live in `mcp_deployments_registry/rust/` and are surfaced to reviewers by the gateway provenance endpoint:

```bash
curl -s https://mcp.rickydata.org/api/attestation/provenance | \
  jq '{securityKernel: .securityKernel, trustPlane: .trustPlane}'
```

The complete trust chain is therefore:

1. Audit this package for encryption, sign-to-derive, and TPM sealing.
2. Verify the gateway lockfile pins the package version and npm integrity.
3. Verify the gateway image provenance and Rust helper hashes match the deployed runtime.

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
# Expected: vaultEncryptionKey is derived from the gateway TPM-backed key source
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
# The key is randomly generated on the VM and sealed to TPM. It must not be
# passed to the runtime container from GitHub secrets.
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

### 8. Verify KFDB TEE Evidence
```bash
# Public machine-readable evidence generated by knowledgeflow_db CI/CD
jq '{subject, source, key_posture, image, security_kernel, proof_status}' evidence/latest.json

# Live production endpoints should match the evidence bundle
curl -s https://tee.knowledgeflowdb.org/health | jq '.security_posture'
curl -s https://tee.knowledgeflowdb.org/api/v1/security/verify | jq '{attestation, security_kernel, checks}'
```

Expected KFDB posture:
- `key_posture.key_source == "tpm_pcr"`
- `key_posture.trust_posture == "enforced"`
- `image.digest` matches `/api/v1/security/verify.attestation.image_digest`
- `security_kernel.source_hash` matches `/api/v1/security/verify.security_kernel.source_hash`
- `lab.instance.confidentialInstanceConfig.confidentialInstanceType == "SEV_SNP"`
- `lab.guest_probe.tpm.pcr_policy_roundtrip.status == "pass"`

### 9. Verify Rust Trust Plane Binding
```bash
curl -s https://mcp.rickydata.org/api/attestation/provenance | \
  jq '.trustPlane | {cargoLockHashSha256, runtimeModes, binaries}'
# Expected during rollout:
# - binaries.sandboxd.matchesManifest == true
# - binaries.trustPlane.matchesManifest == true
# - runtimeModes.sandboxd is shadow, permissive, or enforced
```

## Security Guarantees

With this trust chain:

| Capability | Guarantee |
|------------|------------|
| Read user API keys at rest | Not available without the user-controlled signature or TPM-unsealed per-wallet key |
| Read encrypted data at rest | Not available from stored blobs alone |
| Extract useful secrets from disk | Stored as encrypted blobs; TPM policy or signature is required to decrypt |
| Recover user secrets after TPM reset | Not available unless the original TPM-sealed context and PCR policy can be restored |
| Operator reads BYOK vault key | Deployment must keep this TPM-bound and must not fall back to `LEDGER_ENCRYPTION_KEY` |
| Modify deployed security code silently | Attestation and image provenance should reveal code changes |
| Fake attestation | Blocked by hardware-rooted AMD SEV-SNP verification when checks pass |

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
- **BYOK Vault Key**: Randomly generated on VM and sealed to TPM. It should not be configured as a GitHub secret or passed into the runtime container. If TPM reset occurs, a fresh key is generated only when no existing encrypted wallet data would be orphaned.
- **Recovery**: Automatic unsealing on restart if TPM state unchanged. Deploy auto-heals vTPM slot exhaustion via `tpm2_clear`.
- **Fallback**: Infrastructure keys (JWT, ledger) use env vars if TPM unavailable. BYOK vault key **never** falls back to an operator-readable key.

## Files

- **Agent Gateway Source**: `mcp-agent-gateway/src/secrets/` (TPM model)
- **MCP Gateway Source**: `mcp-gateway/src/secrets/` (in-memory model)
- **Security Kernel Package**: `rickydata_security_kernel/`
- **npm Distribution**: `@rickydata/security-kernel`

## Sync Workflow

The security kernel should be synced from both gateways to the npm package:

1. Agent Gateway security files → TPM-sealed model in security-kernel
2. MCP Gateway security files → In-memory model in security-kernel
3. Both models published together in `@rickydata/security-kernel`

Release discipline requirement: publish the security kernel, update both gateway lockfiles to that exact package version/integrity, and expose that package provenance from the live gateways. Without those three steps, this public repository is a strong review artifact but not a complete proof that the deployed production image is byte-for-byte using the same package.
