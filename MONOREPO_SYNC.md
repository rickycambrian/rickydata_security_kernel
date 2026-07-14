# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `0028ee87cf924a8f8e3f83f4606935e975dcd2ac`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29346751668`
- Synced at: `2026-07-14T16:35:41Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
