# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `fa23c572c0ea7ad4e7a36d4525e19ff8ca1fa6d2`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26864572133`
- Synced at: `2026-06-03T05:25:32Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
