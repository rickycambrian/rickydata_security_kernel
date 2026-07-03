# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `f33b01071ebc49f27f458be06a087b1d73038d1b`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28651022585`
- Synced at: `2026-07-03T10:14:05Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
