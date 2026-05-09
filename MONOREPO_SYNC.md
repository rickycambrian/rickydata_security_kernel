# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `50788d2242a20c9daebd1b1bc2c0acbf6cc5be86`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25589648888`
- Synced at: `2026-05-09T03:35:23Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
