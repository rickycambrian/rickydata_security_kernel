# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `fc93546b83929788b362fa3d447668cbcfb2cec6`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30664426983`
- Synced at: `2026-07-31T21:51:58Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
