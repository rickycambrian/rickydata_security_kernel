# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `0c3d9a77f6a4688b2d89c6827e882a057f7fa917`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `32568772489`
- Synced at: `2026-08-22T11:30:30Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
