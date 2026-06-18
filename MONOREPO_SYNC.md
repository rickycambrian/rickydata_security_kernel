# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `a2a2da0fd173c9c61ec101d282b19ef25921d6f3`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27728261354`
- Synced at: `2026-06-18T01:08:18Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
