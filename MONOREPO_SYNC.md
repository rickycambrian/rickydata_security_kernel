# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `69ddbff6365bae014029edcfe960e9cc47cdd416`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26398765602`
- Synced at: `2026-05-25T12:14:38Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
