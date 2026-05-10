# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `caa53c6522c2fe51b437fdaac2ef8db6de015d7b`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25618525231`
- Synced at: `2026-05-10T03:50:36Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
