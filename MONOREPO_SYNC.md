# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `e2a2ab966554c910fb6eb299079a972977ed24f2`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28729720573`
- Synced at: `2026-07-05T05:19:19Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
