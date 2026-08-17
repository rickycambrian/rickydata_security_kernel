# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `645a4ee93b29469bbac4f0297b3e99d44b4f21bc`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `32079247599`
- Synced at: `2026-08-17T23:47:17Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
