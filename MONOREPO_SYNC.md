# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `0e796c5437f470d58d2bfe2f9133c1b0bab83a6d`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `27483074611`
- Synced at: `2026-06-14T00:27:35Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
