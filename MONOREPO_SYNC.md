# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `7b3fe0ccf6f43f41100fa903cf0b7f94a5c150d5`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31919179264`
- Synced at: `2026-08-16T01:56:36Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
