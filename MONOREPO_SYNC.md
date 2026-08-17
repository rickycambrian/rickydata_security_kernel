# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `73d3d70d9ef655725ec2f14ea35d7561fcad3fb5`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `32063647252`
- Synced at: `2026-08-17T20:45:34Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
