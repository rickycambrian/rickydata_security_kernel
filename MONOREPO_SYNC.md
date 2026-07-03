# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `cb3a3466c8d99d0d9f776bd528af3ef462ecdedc`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28657035834`
- Synced at: `2026-07-03T12:15:48Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
