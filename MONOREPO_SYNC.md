# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `4aae6f41a228b01a9d7f9c0f2f9873d63bc09b89`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28656164178`
- Synced at: `2026-07-03T11:37:26Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
