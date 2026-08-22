# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `dbe0a41a2eecc6858d3504b8502746d9ed62370d`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `32542359506`
- Synced at: `2026-08-22T02:15:08Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
