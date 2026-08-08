# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `d04a4c53d6e618ff58a3e03adf4728cea4ff7805`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31280620657`
- Synced at: `2026-08-08T22:35:13Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
