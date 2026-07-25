# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `bb3cffaa5738d5a2b435ccc291ecbac434e9c3bb`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30135963173`
- Synced at: `2026-07-25T00:50:06Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
