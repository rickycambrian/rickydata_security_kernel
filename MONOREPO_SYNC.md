# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `2a660e3a9c7edb432f8df4ba3bdf854e545d84bf`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29277637625`
- Synced at: `2026-07-13T19:54:25Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
