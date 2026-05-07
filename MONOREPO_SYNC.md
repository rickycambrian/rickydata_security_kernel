# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `fa0dd1fc6ca04b4b878c68ca8a302a0ce4f63ebf`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25517828668`
- Synced at: `2026-05-07T20:07:49Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
