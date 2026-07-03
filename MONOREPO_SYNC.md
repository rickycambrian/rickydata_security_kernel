# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `f6e0c29f2fafaa62609579fe5b18a21a6a83bc3c`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28647625842`
- Synced at: `2026-07-03T08:58:18Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
