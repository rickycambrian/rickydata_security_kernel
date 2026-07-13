# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `5f6f2a94f60f47b554357f421cdb6c0620be0480`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29250983649`
- Synced at: `2026-07-13T13:32:09Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
