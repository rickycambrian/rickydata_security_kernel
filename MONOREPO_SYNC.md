# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `c55991101cf83d3edcbc2dea6d689beaca2e26a7`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `28792847037`
- Synced at: `2026-07-06T13:15:22Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
