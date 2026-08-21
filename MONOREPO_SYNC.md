# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `a80b03ca1ead0ac4c5ddd9b40c0196f2d61a721b`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `32437296518`
- Synced at: `2026-08-21T02:28:13Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
