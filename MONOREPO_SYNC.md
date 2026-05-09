# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `d77f02ac9b095e83b88ceb79b46bad608c933a2f`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25591046962`
- Synced at: `2026-05-09T04:20:42Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
