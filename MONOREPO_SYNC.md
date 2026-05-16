# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `ce8f5023e6478f33c03376c5d6300dc3fae9d616`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25967786913`
- Synced at: `2026-05-16T17:31:10Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
