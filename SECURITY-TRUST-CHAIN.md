# @rickydata/security-kernel Sync Workflow

## Overview

This workflow ensures the security-kernel package stays synchronized between:
- Source: `mcp-agent-gateway/src/secrets/` (where security code is developed)
- Target: `@rickydata/security-kernel` npm package (public distribution)

## When It Runs

- **Manual**: Workflow dispatch
- **Automatic**: After deploy-gateway or deploy-agent-gateway workflows complete

## Trust Chain

The security kernel is the foundation of our zero-knowledge architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                    TRUST CHAIN                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. SECURITY KERNEL (this package)                          │
│     ├─ AES-256-GCM encryption                                │
│     ├─ Sign-to-derive (operator cannot read)                │
│     └─ TPM sealing with PCR binding                          │
│                           │                                      │
│                           ▼                                      │
│  2. MCP GATEWAY TEE (mcp-gateway)                        │
│     ├─ AMD SEV-SNP confidential VM                          │
│     ├─ Attestation verified at /health                       │
│     └─ Uses security-kernel for secret management            │
│                           │                                      │
│                           ▼                                      │
│  3. AGENT GATEWAY TEE (mcp-agent-gateway)                │
│     ├─ AMD SEV-SNP confidential VM                          │
│     ├─ Attestation verified at /health                       │
│     └─ Uses security-kernel for BYOK secrets                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Verification Commands

### 1. Check Security Kernel npm Package
```bash
npm view @rickydata/security-kernel version
npm view @rickydata/security-kernel license
```

### 2. Verify Agent Gateway TEE
```bash
curl -s https://agents.rickydata.org/health | jq '.securityPosture'
# Returns: { tee: "SEV-SNP", attestation: "verified", codeHash: "sha256:..." }
```

### 3. Verify MCP Gateway TEE
```bash
curl -s https://mcp.rickydata.org/health | jq '.securityPosture'
# Returns: { tee: "SEV-SNP", attestation: "verified", codeHash: "sha256:..." }
```

### 4. Verify Both TEEs Use Same Security Kernel
```bash
# Get code hashes from both gateways
AGENT_HASH=$(curl -s https://agents.rickydata.org/health | jq -r '.securityPosture.codeHash')
MCP_HASH=$(curl -s https://mcp.rickydata.org/health | jq -r '.securityPosture.codeHash')

# Compare
if [ "$AGENT_HASH" = "$MCP_HASH" ]; then
  echo "✅ Both TEEs use identical security kernel"
else
  echo "⚠️ TEEs use different security kernels"
fi
```

## Manual Sync Steps

If you need to manually sync the security kernel:

```bash
# 1. Copy source files from agent-gateway
cp mcp-agent-gateway/src/secrets/encryption.ts rickydata_security_kernel/src/
cp mcp-agent-gateway/src/secrets/key-derivation.ts rickydata_security_kernel/src/
cp mcp-agent-gateway/src/secrets/tpm-vault.ts rickydata_security_kernel/src/

# 2. Update version
cd rickydata_security_kernel
npm version patch

# 3. Build and test
npm install
npm run build
npm test

# 4. Publish
npm publish --access public
```

## Security Guarantees

With this trust chain:

| Capability | Guarantee |
|------------|------------|
| Read user API keys | ❌ Impossible (Sign-to-Derive) |
| Read encrypted data | ❌ Impossible (key derived from signature) |
| Extract secrets from disk | ❌ Impossible (TPM-sealed) |
| Modify security kernel | ❌ Impossible (attestation detects) |
| Fake attestation | ❌ Impossible (hardware-rooted) |

## Files

- Source: `mcp-agent-gateway/src/secrets/`
- Package: `rickydata_security_kernel/`
- npm: `@rickydata/security-kernel`
