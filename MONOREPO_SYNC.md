# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `b75fee1a12106692b25ad907cda7de9a671bd3c1`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26076646128`
- Synced at: `2026-05-19T05:12:44Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
