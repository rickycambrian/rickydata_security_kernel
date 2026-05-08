# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `e3a1b34e73cf5d1e2d8f8e21e66b6fb9ebe24ebe`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25575658753`
- Synced at: `2026-05-08T19:59:32Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
