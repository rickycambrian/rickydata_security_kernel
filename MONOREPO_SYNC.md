# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `ee66c4deee3dee4aab7c8b5655f2a489d6b88802`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26703582319`
- Synced at: `2026-05-31T05:19:59Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
