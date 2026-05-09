# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `0081eaaeda3a8ab5b25ba4f7da0e12cd2c2192de`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25593639239`
- Synced at: `2026-05-09T06:28:47Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
