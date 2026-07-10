# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `37f4d4d07ec61be93ead95769b881f5116cd03cc`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29084241647`
- Synced at: `2026-07-10T10:26:10Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
