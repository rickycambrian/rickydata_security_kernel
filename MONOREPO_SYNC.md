# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `88f82cec9d19b124be6c32bcd3a689bee2a7c288`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25900517037`
- Synced at: `2026-05-15T05:06:05Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
