# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `b0a783567a69dd61c78a63fa436c1b7041dbee5b`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25476104626`
- Synced at: `2026-05-07T04:50:29Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
