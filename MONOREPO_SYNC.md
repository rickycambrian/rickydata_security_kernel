# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `0a978c83ad8418d64be68b3e0e9c3200576d74a7`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `29345265697`
- Synced at: `2026-07-14T15:48:54Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
