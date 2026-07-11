# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `ab7f20f86b8c099718e18932e8e8cd3a9441af5e`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29145403649`
- Synced at: `2026-07-11T08:58:49Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
