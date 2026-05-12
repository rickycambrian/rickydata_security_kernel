# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `9a8a2e1570099f774924fc94825d5c24c50a4bc1`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25711228039`
- Synced at: `2026-05-12T03:45:21Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
