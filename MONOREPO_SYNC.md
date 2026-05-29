# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `da4e0a555019713d3a2736ed48d9782f6f8f91ce`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26618561427`
- Synced at: `2026-05-29T05:17:12Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
