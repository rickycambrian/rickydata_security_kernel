# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `b6e68f1d1c3d5ba02b16791d7397ad552b5a5cf0`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25467918597`
- Synced at: `2026-05-07T00:19:36Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
