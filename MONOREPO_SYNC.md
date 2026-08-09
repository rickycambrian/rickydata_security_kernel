# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `a9fa1cdd465d4ef1e3a552b2b191b31dcd4106e5`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31325130378`
- Synced at: `2026-08-09T19:00:27Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
