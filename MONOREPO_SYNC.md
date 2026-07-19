# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `08c6dff35f6f8611d8e1c059806dca2a7b3d6877`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29706793129`
- Synced at: `2026-07-19T23:43:33Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
