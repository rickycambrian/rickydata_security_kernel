# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `9fe8f8e630c7b1d598e882ab662e0e7ffa17c362`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27750325703`
- Synced at: `2026-06-18T10:09:35Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
