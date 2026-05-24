# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `c3a3afffcc45ad1ac8ebb4bffa7f00049c479f69`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26350236377`
- Synced at: `2026-05-24T03:31:19Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
