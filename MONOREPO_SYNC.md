# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `aa276bfddbc1e6bb66d91c0295505cdcacfc64e4`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `29736059805`
- Synced at: `2026-07-20T11:03:21Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
