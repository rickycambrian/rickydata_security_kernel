# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `96ee9ad1dfbefbe83cc0562fd602f3fe8c565e41`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25952716781`
- Synced at: `2026-05-16T04:56:06Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
