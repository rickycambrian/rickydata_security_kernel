# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `c8ec75ce576cfa1e95b063535e867ca6eb93e3d1`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28612717725`
- Synced at: `2026-07-02T19:05:02Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
