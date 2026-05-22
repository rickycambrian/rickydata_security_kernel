# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `2c87714fc3d75e07eb52baadc2868686a118dc56`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `26265403101`
- Synced at: `2026-05-22T03:07:56Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
