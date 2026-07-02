# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `98fa1a6edcce243ab03c37b7de8c09b09493e9fe`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28618708930`
- Synced at: `2026-07-02T20:51:35Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
