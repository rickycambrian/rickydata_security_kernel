# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `dbf5468f09f2415bc9f53b13c157c3b3895fe02e`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27221343484`
- Synced at: `2026-06-09T17:37:59Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
