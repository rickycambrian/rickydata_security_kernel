# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `be21dc534b4118d36a282c3e8f5a815d39f8a391`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `28975773263`
- Synced at: `2026-07-08T21:30:47Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
