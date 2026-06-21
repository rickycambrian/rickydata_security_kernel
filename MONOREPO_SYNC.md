# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `88e7d4f1fe71dd3ee9ebe0471fdb53ad47cda2bb`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27887611351`
- Synced at: `2026-06-21T00:27:07Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
