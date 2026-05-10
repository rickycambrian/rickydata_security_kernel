# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `d035fe3ddb4034e15f2f196aaf73b465ba102dd0`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25621541360`
- Synced at: `2026-05-10T06:37:07Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
