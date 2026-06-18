# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `d5f0a17344fa1b6e7aaec77c6895e931e176a5f4`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27795286282`
- Synced at: `2026-06-18T23:55:23Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
