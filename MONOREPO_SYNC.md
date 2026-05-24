# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `75a0e0338fe523ee5bbd4f8104bb7d076ab25dbe`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `26354269110`
- Synced at: `2026-05-24T07:07:33Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
