# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `0fc47c154120dc84cb74b9571dbe1d21960dfdd9`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27228765192`
- Synced at: `2026-06-09T19:29:55Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
