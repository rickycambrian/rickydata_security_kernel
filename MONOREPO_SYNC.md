# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `b8c0fb3d0213543b94abb9a17ed1d2a7d25bef40`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25605836621`
- Synced at: `2026-05-09T16:44:44Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
