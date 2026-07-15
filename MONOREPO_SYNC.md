# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `68d3acc0fb533b0bf2bc11c1e34f9f8b05cabb30`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29456189527`
- Synced at: `2026-07-15T23:51:24Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
