# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `a8973fded9e2203ab8e376831948bc7ddc3992d6`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31335053100`
- Synced at: `2026-08-09T21:37:54Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
