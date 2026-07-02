# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `f888fc6b33bb7204c9fb26b619655be35b89b7df`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28626438541`
- Synced at: `2026-07-02T23:26:27Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
