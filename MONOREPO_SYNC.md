# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `d27d2b9aee137f9487a8a0374b3232d4f9d91def`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `29498460841`
- Synced at: `2026-07-16T12:53:28Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
