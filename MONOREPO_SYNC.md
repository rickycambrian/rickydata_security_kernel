# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `bedf0b9e5013d7400078218a8a0fb903b73cbc78`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `26009886804`
- Synced at: `2026-05-18T02:37:50Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
