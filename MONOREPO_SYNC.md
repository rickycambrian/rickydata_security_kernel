# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `f4c45f2b6ded6da3092cd2e04e61bbf8f7b7a9b4`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28132109273`
- Synced at: `2026-06-24T22:31:02Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
