# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `20e874c05993a0bd74dbf24c78d59c70f9bab48a`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `26342644844`
- Synced at: `2026-05-23T20:48:28Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
