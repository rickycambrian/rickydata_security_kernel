# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `ef5f63bedd1c1ed03025e1fe7d7b58c0f953c72b`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26799260422`
- Synced at: `2026-06-02T05:24:31Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
