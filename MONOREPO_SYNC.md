# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `cefd7aabf5723cb33888e2422e9e854f1a130623`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29701267130`
- Synced at: `2026-07-19T20:40:29Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
