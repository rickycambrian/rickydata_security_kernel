# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `bdd4b284c9867792b362e912f5ce4ebeb5bcee02`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29054754004`
- Synced at: `2026-07-09T23:08:14Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
