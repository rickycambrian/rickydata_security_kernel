# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `22b4bf91c74cadd5fc947b4e0de95a946b7e11ac`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27358502372`
- Synced at: `2026-06-11T16:11:40Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
