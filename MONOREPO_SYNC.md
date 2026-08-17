# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `4ccfb978a36f4129cfc2f790f3e787ce95c97295`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `32068211374`
- Synced at: `2026-08-17T22:32:44Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
