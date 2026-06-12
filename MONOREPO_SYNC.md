# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `7f46296e78285338def50ab3d6a9c4b3e5444294`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27443776887`
- Synced at: `2026-06-12T21:57:34Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
