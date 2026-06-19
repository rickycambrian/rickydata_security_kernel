# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `56dd113d4f0b14f2405f122848b6099f5a72b03d`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27797446294`
- Synced at: `2026-06-19T00:56:01Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
