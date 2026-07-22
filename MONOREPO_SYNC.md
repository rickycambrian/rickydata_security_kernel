# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `434cc47d33f15c85e6c7c3260f1172e6150ab107`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29945644029`
- Synced at: `2026-07-22T18:42:14Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
