# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `c371c6d40d5defb798d97e809c83e578a4e8d489`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29119171639`
- Synced at: `2026-07-10T20:56:07Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
