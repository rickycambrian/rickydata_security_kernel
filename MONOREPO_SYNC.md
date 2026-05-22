# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `f6a3b0b5d2df7ac32549713dc04f86d8f1bdc8da`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26307305173`
- Synced at: `2026-05-22T20:09:41Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
