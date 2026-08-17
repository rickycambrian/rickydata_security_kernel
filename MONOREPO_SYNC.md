# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `6e5e5d02eefec32058be8bf7f6171d0037a6e4fb`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `32036755192`
- Synced at: `2026-08-17T14:44:39Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
