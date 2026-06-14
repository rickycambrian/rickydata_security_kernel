# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `39a64a9ad600d11c08fa8b98439c043646cd294e`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `27483827881`
- Synced at: `2026-06-14T01:05:03Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
