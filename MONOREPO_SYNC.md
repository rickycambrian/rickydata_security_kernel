# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `30c9a6f8771e5c531b32e4f596a21071819ba415`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29154296627`
- Synced at: `2026-07-11T14:17:56Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
