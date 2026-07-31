# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `97cc6bb9412b951262414c28f28c5b6fcd0d0b76`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `30592935182`
- Synced at: `2026-07-31T00:31:42Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
