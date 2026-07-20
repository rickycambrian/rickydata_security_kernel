# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `80e7a05a9155ab6618e875cf8a441a9c07fd9b72`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29712151626`
- Synced at: `2026-07-20T02:44:00Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
