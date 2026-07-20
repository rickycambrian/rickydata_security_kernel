# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `e1c9965d94a18fb02813c40c1b6295a49578eccb`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29750687552`
- Synced at: `2026-07-20T14:59:00Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
