# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `97b71c85d39d0880d4bd67a0dd54d2b361de4883`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28917353279`
- Synced at: `2026-07-08T05:00:24Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
