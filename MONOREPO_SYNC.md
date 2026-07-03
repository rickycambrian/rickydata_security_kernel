# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `ebb3b024e16eb77ec10d6e4ba16e05589f2d26be`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28670280392`
- Synced at: `2026-07-03T16:15:03Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
