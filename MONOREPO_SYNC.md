# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `91e4819d3b6e6442d493c8c6c0cb4343418e611e`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27846822584`
- Synced at: `2026-06-19T21:26:42Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
