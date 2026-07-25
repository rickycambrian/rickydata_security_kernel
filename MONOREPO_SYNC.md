# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `ac261b51efe52ef6c9dce0d38ffc4efcc9f001e4`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `30166847092`
- Synced at: `2026-07-25T17:21:41Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
