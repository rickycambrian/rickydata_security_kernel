# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `c8c75854a0b58e3e2619bff48e154a99e0fdbe4b`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `29849821681`
- Synced at: `2026-07-21T16:59:16Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
