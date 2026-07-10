# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `ad41eb072f48907a0a2097db20e8ea76134cc055`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29118725736`
- Synced at: `2026-07-10T20:19:18Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
