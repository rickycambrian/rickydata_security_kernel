# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `139f65f35111f7d15da4aba52c628aafc5b110bc`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29281981524`
- Synced at: `2026-07-13T21:00:35Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
