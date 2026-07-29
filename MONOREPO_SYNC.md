# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `aa1318b8b934d6ef63b6a4d6d8984f3aed58b5c0`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30441704145`
- Synced at: `2026-07-29T11:02:03Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
