# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `ec04189c68c20ff66c4357e0cb406c991f8e8943`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `32423336985`
- Synced at: `2026-08-21T00:11:11Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
