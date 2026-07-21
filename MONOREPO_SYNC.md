# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `a99461d2cb6e2517e80cf3c092cca272836a2765`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29827651674`
- Synced at: `2026-07-21T12:22:35Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
