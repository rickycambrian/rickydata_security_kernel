# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `782291745b3158c9b1b6b47b2232be8e2646ac54`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29377591554`
- Synced at: `2026-07-15T00:38:48Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
