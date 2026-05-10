# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `38e0b0de31525f090f0c637e5ca5ab2f093df8b6`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25628292537`
- Synced at: `2026-05-10T12:41:33Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
