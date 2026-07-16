# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `4f1313b5bc9b2366ae1a3a46c8cef4b13e3c7c87`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29471192353`
- Synced at: `2026-07-16T05:03:35Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
