# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `26e5c7d06de25372431b9552a0774b38bdea45ee`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29190056876`
- Synced at: `2026-07-12T11:39:12Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
