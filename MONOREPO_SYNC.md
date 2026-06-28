# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `effe8778a799c1421d128fe527b3d829fcb8a7ec`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28311744820`
- Synced at: `2026-06-28T05:28:37Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
