# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `b20bf94f4909963e71e5e1a7b3f8f8a8b60faaa1`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `32143928718`
- Synced at: `2026-08-18T14:26:17Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
