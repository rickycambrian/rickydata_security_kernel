# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `e4320114bfaa7bd63569ede4a3e97c87abb3faa3`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29324872208`
- Synced at: `2026-07-14T10:58:39Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
