# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `b62c4b712aba298c89da3b8bf24667590bd18d09`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25319732098`
- Synced at: `2026-05-04T13:03:05Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
