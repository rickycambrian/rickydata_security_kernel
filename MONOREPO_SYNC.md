# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `e29334a4ba2cebb1a660d7ca548f1566d7f1e1ed`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29464402100`
- Synced at: `2026-07-16T02:23:30Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
