# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `4007a70436321ffc0f66f2d0f04bcc0ebef87919`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `32537798803`
- Synced at: `2026-08-22T00:21:27Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
