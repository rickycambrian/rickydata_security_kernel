# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `491ba2f721026c44831a10eb51b64cf3777bf1b4`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25528716927`
- Synced at: `2026-05-08T00:22:44Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
