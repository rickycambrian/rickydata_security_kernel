# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `2f36f0f5e75c503ab7afd1ba9f62202109f1130d`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `29621259256`
- Synced at: `2026-07-17T23:55:31Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
