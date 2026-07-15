# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `d68f5ec61948b4bfcb7bcbaca809737dc9e8cde2`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29446270265`
- Synced at: `2026-07-15T21:03:51Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
