# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `e5fb9a640e5cc99568a53abecc755e7cdf6f8cfe`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25741029087`
- Synced at: `2026-05-12T14:56:57Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
