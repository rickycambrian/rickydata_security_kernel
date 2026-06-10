# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `54bc33961e1334823fd2b9f06b705b9ee71a85db`
- Source workflow: `Deploy MCP Gateway to TEE`
- Source workflow run: `27270455469`
- Synced at: `2026-06-10T11:01:57Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
