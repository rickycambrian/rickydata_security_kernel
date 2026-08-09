# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `c546759a4a1fb1348763ecb3c42c8d2f91881ac2`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31337981459`
- Synced at: `2026-08-09T22:40:13Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
