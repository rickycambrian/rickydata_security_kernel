# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `22b4812aa773d5f71b0c0eaecb0bf95fe1aa762b`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `26487317182`
- Synced at: `2026-05-27T02:59:06Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
