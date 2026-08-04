# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `f7f954850d4cb8591f1d808abeaf37ad03b2e3e5`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30865717982`
- Synced at: `2026-08-04T01:15:21Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
