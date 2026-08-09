# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `d7b302cc30e8f2ec7cdb676fbaca38634b2c680d`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31324569073`
- Synced at: `2026-08-09T17:21:08Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
