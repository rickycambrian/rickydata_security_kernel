# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `fa46e557540dee69876a50328f63b9cfb1a22f1e`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29394320210`
- Synced at: `2026-07-15T07:13:04Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
