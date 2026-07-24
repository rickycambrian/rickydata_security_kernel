# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `42ded9f10ab99fbef355ae1b7601f93f5a91d16c`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30124379490`
- Synced at: `2026-07-24T21:35:39Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
