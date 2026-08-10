# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `abf1c2c27d2bbcf53d80427b55fe0cf38d00dcf0`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31344704065`
- Synced at: `2026-08-10T01:38:41Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
