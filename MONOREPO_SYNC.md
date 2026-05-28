# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `6c9dccdf49a1876191fb38e27d0f45eb375c60f5`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26555234822`
- Synced at: `2026-05-28T05:16:02Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
