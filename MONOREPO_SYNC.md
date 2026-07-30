# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `5a0bf7de34605a93de80d30eb26785ad39593f89`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30500553306`
- Synced at: `2026-07-30T00:37:18Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
