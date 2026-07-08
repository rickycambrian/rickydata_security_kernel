# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `27170d42bf161cc4e88dba50ba46e01135d0a315`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `28977647118`
- Synced at: `2026-07-08T22:00:05Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
