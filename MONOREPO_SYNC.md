# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `7980449aa269bb918ef440ff6c13c19463d7aa8b`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26335254876`
- Synced at: `2026-05-23T15:21:01Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
