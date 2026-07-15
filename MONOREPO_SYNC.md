# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `8355bf16c9efc7d2c3c9eff05662e90b835eea8a`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29432812233`
- Synced at: `2026-07-15T17:23:40Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
