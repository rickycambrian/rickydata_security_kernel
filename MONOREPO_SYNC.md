# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `4c6d98366118cd9e18cffc50bb19e7158a617f2f`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28278791942`
- Synced at: `2026-06-27T05:14:50Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
