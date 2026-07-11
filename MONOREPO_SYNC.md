# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `d7a7d0b65f484744be4bfec8d34d5fcda579dc92`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29168841347`
- Synced at: `2026-07-11T22:07:11Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
