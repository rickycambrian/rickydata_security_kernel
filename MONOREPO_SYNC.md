# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `c370cd0b2f39dd7fecee0330c04f31d157a4a216`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31343214721`
- Synced at: `2026-08-10T01:01:49Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
