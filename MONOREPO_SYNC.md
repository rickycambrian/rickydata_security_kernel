# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `ec581ee3aacabbed4c874cdca408c8e0e9b58bd9`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25581945530`
- Synced at: `2026-05-08T22:30:43Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
