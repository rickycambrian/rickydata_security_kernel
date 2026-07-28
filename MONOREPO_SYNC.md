# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `fda0fb4dff22b793d7d16375bd46a50dc3d03ba7`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30374530426`
- Synced at: `2026-07-28T16:17:35Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
