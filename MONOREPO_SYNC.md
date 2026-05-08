# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `86575a13ae6f4a3cf6d1849ebbc9ae72282dec07`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25583763705`
- Synced at: `2026-05-08T23:25:59Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
