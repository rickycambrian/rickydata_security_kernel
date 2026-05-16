# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `b691471a3d060aa81e86841fb0270dcffbb1e522`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25950457374`
- Synced at: `2026-05-16T02:58:20Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
