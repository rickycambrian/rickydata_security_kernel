# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `d3640c2ef388aad801cf17a7e46f7e367a5b947f`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25620897562`
- Synced at: `2026-05-10T05:59:42Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
