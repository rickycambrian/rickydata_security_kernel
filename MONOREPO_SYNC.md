# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `1c7b59f10af7258ff09e1b3669cb25f1d21b695e`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27841614116`
- Synced at: `2026-06-19T19:25:50Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
