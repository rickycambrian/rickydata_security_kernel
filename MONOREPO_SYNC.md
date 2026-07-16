# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `4bb3b5f47c6bc0b058313fa1ff641634e0c2ef22`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29462589641`
- Synced at: `2026-07-16T01:41:45Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
