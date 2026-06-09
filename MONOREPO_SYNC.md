# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `7f0a3f79a72f1a0d28ac4e2691b915a025b85731`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27205008269`
- Synced at: `2026-06-09T12:39:36Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
