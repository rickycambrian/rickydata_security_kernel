# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `2488ec3c73ce7e10c5157972df0fbdb3daa9ec9e`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `29114872928`
- Synced at: `2026-07-10T18:52:39Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
