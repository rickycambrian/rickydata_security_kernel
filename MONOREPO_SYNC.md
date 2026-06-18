# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `a1e8ef886138acf98b30b2e1ca1b078817e00c4c`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27778481257`
- Synced at: `2026-06-18T18:24:09Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
