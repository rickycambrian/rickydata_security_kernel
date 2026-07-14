# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `b3531cacb580d977aa95cc23128a400b6d2dc8dd`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29304487485`
- Synced at: `2026-07-14T04:28:53Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
