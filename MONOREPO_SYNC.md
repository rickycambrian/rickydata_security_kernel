# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `4bb72e3da324ff4d64037f67374baf9fdcd86f2c`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29633119067`
- Synced at: `2026-07-18T06:28:53Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
