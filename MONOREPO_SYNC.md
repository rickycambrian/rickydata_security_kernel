# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `d7860ced6c579fb7d43a5ba6fc8ab1f2cf92eab2`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30164143027`
- Synced at: `2026-07-25T16:14:08Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
