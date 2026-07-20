# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `3f51127fcaec4b12016d1e60dd872f777f1a8728`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29785883366`
- Synced at: `2026-07-20T23:31:33Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
