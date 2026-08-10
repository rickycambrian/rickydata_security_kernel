# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `91936fcc5b51f470a826ce124afffb4aa83fae50`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31340484468`
- Synced at: `2026-08-10T00:07:45Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
