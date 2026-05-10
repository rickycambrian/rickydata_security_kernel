# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `354c8b0fab1453fed0cb52a55b4ed70941e5fc21`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25619304959`
- Synced at: `2026-05-10T04:25:15Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
