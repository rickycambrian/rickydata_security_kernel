# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `194a3e8a0f20f2005608ec4a831a8a87417084d5`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `28783735328`
- Synced at: `2026-07-06T10:42:16Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
