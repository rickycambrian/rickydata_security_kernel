# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `830a1c6b0b42342f4dd04b56fcf266b2d65893a4`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29334437847`
- Synced at: `2026-07-14T13:39:08Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
