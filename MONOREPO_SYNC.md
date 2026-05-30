# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `f747bd6306829fbb418f5d47b0e6e9889ec0b88d`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26681502035`
- Synced at: `2026-05-30T10:57:38Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
