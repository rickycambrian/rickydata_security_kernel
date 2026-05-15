# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `a93159ba08d437eaa578b110cd2139fb9f0342f9`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25944233084`
- Synced at: `2026-05-15T22:53:04Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
