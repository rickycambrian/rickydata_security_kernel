# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `59321f1b15aa4198b345f20402b9aad3ccd1f736`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `26482273331`
- Synced at: `2026-05-27T00:29:34Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
