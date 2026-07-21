# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `8ae37124a58a2b7102d69e3e90799c73e3733fc9`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29827681441`
- Synced at: `2026-07-21T12:50:54Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
