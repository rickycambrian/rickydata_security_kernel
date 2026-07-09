# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `ac844201b924431b1dd2a470e6e5e4cc6a16d2ca`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `28986633395`
- Synced at: `2026-07-09T01:26:14Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
