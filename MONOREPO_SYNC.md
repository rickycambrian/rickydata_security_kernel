# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `8c8e9f216ab32deaa7a5f341b58c9d07547c72f2`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29389604760`
- Synced at: `2026-07-15T05:43:55Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
