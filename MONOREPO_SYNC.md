# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `94e6fc4285573e39afe8920316b38c43ddcc0073`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29454105076`
- Synced at: `2026-07-15T23:08:00Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
