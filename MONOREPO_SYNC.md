# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `c3dbcd46a3a2c1cabe775a7eae3b1839e181c33f`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26321231128`
- Synced at: `2026-05-23T03:09:10Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
