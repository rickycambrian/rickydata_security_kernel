# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `8e6bbb1415b91a28f534ae7db98b19ebfbefbbe6`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31319673774`
- Synced at: `2026-08-09T15:32:01Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
