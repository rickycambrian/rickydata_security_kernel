# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `9b80f9641b2ecbe5706fe8448e6e90cea9e13f83`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25624460324`
- Synced at: `2026-05-10T09:16:32Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
