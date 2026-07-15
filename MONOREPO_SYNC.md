# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `cd8b35dd8a8280fb4cf4e96ff70b5dc5a0b601a5`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29430308951`
- Synced at: `2026-07-15T16:42:46Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
