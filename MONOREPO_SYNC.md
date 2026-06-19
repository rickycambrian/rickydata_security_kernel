# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `962f3a02e9e8ae30e449bd81131d6ce3880ee1b1`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27850397445`
- Synced at: `2026-06-19T22:38:47Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
