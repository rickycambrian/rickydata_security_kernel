# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `65691514cd40af007d983ad94f15c4fe14ac0da2`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25510806170`
- Synced at: `2026-05-07T17:33:46Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
