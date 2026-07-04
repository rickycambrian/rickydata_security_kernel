# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `436f52f986f9d0a19f1a131f7d195666168dadc2`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `28707895884`
- Synced at: `2026-07-04T13:58:02Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
