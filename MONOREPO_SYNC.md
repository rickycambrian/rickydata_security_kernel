# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `52d3213b60d54e0c4c3c6f4da18a1c167888ab92`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27456994213`
- Synced at: `2026-06-13T05:25:51Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
