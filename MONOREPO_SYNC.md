# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `6fc0eb6f58771f731b3b9fbea4f18b39b2b2038f`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29112656785`
- Synced at: `2026-07-10T19:03:39Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
