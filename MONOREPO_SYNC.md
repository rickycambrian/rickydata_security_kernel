# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `98783f81bb9698eeadd5b7e11f7f05aad1af4050`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29935031583`
- Synced at: `2026-07-22T16:20:40Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
