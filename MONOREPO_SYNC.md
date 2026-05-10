# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `b29fc8c6224db5ff4fb49e73404e34466f37a79e`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25618091825`
- Synced at: `2026-05-10T03:25:55Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
