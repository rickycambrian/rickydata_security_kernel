# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `07981f67a504d6ac06d27cf323e77b232c1ff99e`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25622101016`
- Synced at: `2026-05-10T07:09:57Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
