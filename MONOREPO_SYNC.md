# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `85d48ad956b274fb8018bf3e54004ebe7d445c4d`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `32532378665`
- Synced at: `2026-08-21T22:57:49Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
