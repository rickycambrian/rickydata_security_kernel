# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `65c5673a64e59ecb3c2f0aefadd62a9e6822ed8b`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26262192010`
- Synced at: `2026-05-22T01:30:27Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
