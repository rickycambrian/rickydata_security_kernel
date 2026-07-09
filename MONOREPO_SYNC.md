# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `f12c4d1827b875de3c61c6bb0ade46b31970ac67`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28989254259`
- Synced at: `2026-07-09T02:54:08Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
