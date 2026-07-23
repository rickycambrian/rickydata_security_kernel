# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `8f9818400ba9d6fd6897f1733cb8ee103a74e0c5`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `29998470800`
- Synced at: `2026-07-23T10:30:47Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
