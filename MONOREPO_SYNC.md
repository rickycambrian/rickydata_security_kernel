# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `b572b7112a7a09b82a0c7e3805432d85b1ac020b`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29038306564`
- Synced at: `2026-07-09T18:27:52Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
