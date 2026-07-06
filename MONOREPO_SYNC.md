# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `d572d09186c3747f75c73a4984a1f0d39978ee0d`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28780358419`
- Synced at: `2026-07-06T09:45:17Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
