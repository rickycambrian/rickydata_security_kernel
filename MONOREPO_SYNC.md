# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `52b079dc02ce3a92fb1d9c4e90b7f865af62c7b7`
- Source workflow: `manual-local-sync-after-ci`
- Source workflow run: `25293721610`
- Synced at: `2026-05-03T23:21:09Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
