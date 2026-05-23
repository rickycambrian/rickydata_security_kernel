# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `981d8fcd5d09ecab2068fcaa282e6149afd9d489`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `26332634523`
- Synced at: `2026-05-23T12:53:16Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
