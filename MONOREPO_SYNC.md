# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `868d430964b700bb6e47456ccbe0bf41b11a614c`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `26296454953`
- Synced at: `2026-05-22T15:45:30Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
