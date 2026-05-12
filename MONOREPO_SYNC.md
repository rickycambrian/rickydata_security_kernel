# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `a18bdc9c4f9046dbd441a5cf8a732441d03ec255`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25755558878`
- Synced at: `2026-05-12T19:26:24Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
