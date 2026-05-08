# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `963357f2c9cbb256738582d59a2cbae9e1ba3e12`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25533893611`
- Synced at: `2026-05-08T03:13:23Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
