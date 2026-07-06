# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `bc5437439e424fe6d25a8241801f5f3d5d4b5883`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28783853012`
- Synced at: `2026-07-06T11:19:16Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
