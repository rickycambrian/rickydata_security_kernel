# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `1a30eb86dbddbf42ff4e1a4afbfe6b96bc6584c3`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30573021730`
- Synced at: `2026-07-30T21:23:20Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
