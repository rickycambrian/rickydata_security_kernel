# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `2826c33d698a3d11945c86a20a29b4e69b50e76b`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26008627093`
- Synced at: `2026-05-18T02:24:14Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
