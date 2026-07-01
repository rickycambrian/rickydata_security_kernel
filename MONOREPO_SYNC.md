# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `0e5c2af17ab1b4e36930ecf2f97fa435fc55fd68`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28516237790`
- Synced at: `2026-07-01T12:44:24Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
