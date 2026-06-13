# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `c34e2a72b7acfb8eb0d7207f64b5d580deb160ac`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `27475685867`
- Synced at: `2026-06-13T19:05:55Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
