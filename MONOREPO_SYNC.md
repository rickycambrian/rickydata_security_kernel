# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `cab393ac37f3cf1cc44ab9f0a11f88d052cc16b0`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25569049944`
- Synced at: `2026-05-08T17:35:49Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
