# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `81e5b38c84e14952bd577fc3d1c3df89bca15de9`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29850171520`
- Synced at: `2026-07-21T17:49:09Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
