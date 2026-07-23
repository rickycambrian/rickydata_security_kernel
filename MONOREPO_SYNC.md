# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `7e6cd5de3778a3120c4e4a6467ff74a109bcf6b1`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `30032824742`
- Synced at: `2026-07-23T18:32:37Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
