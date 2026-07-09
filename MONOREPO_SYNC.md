# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `6487c3e66d4a471b85f3d5e7afbe5f4321202e94`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `29050664181`
- Synced at: `2026-07-09T21:34:15Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
