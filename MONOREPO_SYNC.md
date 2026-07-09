# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `1b9ee36d125610967735cacbc8ec17d83982be4f`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29045730133`
- Synced at: `2026-07-09T20:28:33Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
