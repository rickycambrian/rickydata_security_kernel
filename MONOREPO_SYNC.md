# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `a1dbf591aa1f8b660f8518ca3d2840ec6d3ca6de`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29542648884`
- Synced at: `2026-07-17T00:21:01Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
