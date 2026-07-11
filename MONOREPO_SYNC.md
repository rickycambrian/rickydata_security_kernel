# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `4aa5a5c0c2beb07ffdec136f10f37ce43cecd6d4`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29139498658`
- Synced at: `2026-07-11T05:00:29Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
