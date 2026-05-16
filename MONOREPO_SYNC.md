# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `9fd19fb343bc39f0711ce6091f8c45929350a301`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25969069379`
- Synced at: `2026-05-16T18:31:29Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
