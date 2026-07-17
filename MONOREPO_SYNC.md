# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `248397bcccb02c5e0d08a4aa62fb34698fbdcba0`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29592570837`
- Synced at: `2026-07-17T16:15:25Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
