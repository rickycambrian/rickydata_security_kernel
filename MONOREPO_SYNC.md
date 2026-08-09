# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `f9198bafc8351dfee10ac1723a247f3b89b5a6a5`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31302721591`
- Synced at: `2026-08-09T10:00:19Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
