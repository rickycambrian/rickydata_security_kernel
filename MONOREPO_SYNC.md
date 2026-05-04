# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `98e161740b3ac894ac4e1f52ffebc8181ffc7f9b`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25299055946`
- Synced at: `2026-05-04T03:44:51Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
