# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `a58842f2dd40fde72a50037a1b99c4c7801ee64d`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25602034499`
- Synced at: `2026-05-09T13:39:02Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
