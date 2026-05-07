# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `340f8f1dc0a1a69b127184dfcbbea9b325cea2d6`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25496357647`
- Synced at: `2026-05-07T13:06:42Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
