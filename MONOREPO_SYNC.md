# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `d8d60cd44613d353df5b8c3d338fc7a409ff4cf7`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30147855082`
- Synced at: `2026-07-25T07:12:23Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
