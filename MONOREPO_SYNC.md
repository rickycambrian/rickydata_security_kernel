# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `136b2a150dc0c2e8f51c6c0fb487e40c6ef1d622`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31299654293`
- Synced at: `2026-08-09T07:44:21Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
