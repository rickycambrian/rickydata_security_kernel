# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `d0fc4fc5d57d6d2fe3f3e436eecadbb7cedd423a`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31969403211`
- Synced at: `2026-08-16T20:46:49Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
