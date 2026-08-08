# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `230aba32c4d516c62ba86cde378947b0fd04d87e`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31272879306`
- Synced at: `2026-08-08T19:53:39Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
