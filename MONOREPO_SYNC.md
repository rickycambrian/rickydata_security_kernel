# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `17be533ca0129edfc03d0fb894d93b8a52143ed8`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29597943908`
- Synced at: `2026-07-17T17:50:59Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
