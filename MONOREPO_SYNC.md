# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `90e00cf6e2f37a1e2a611c1061a48a2caacf9ea9`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25778493137`
- Synced at: `2026-05-13T05:03:42Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
