# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `e61ff5108fc489ba0fc4f880ef1f90dfe1fb2faa`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26312456945`
- Synced at: `2026-05-22T22:16:38Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
