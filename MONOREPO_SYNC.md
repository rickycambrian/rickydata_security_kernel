# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `716037e6c7b2b5e5c489c8e584c2350fef8fb4a6`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25975137000`
- Synced at: `2026-05-16T23:23:13Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
