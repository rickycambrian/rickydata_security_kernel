# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `8c3d8da7d787c4bfef620e125432d4e5eee9b1c3`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30152880024`
- Synced at: `2026-07-25T10:01:10Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
