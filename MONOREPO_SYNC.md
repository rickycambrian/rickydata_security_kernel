# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `6a497f8ac6ff3fc5ae0bf726ec7ac627fc58666d`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29122913848`
- Synced at: `2026-07-10T21:34:11Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
