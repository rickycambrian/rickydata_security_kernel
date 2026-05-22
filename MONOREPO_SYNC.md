# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `11fcb2bb0481f4c8a138ba59769a4b52a4db587f`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26267416601`
- Synced at: `2026-05-22T04:21:48Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
