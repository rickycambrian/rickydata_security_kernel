# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `be3abf531e3b885d0f0c989944cf4dca1c8c0c48`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26337832732`
- Synced at: `2026-05-23T17:02:56Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
