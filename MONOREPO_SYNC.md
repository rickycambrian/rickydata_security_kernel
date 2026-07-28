# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `8734b0c776ce2dd6c54edb3c13839c8aa9882b4f`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30400691245`
- Synced at: `2026-07-28T22:04:50Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
