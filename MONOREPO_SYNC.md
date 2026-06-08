# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `1dc9714cb3dd86fa3a4c3e73e7a5ed86f9ace6f1`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27169923935`
- Synced at: `2026-06-08T22:39:51Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
