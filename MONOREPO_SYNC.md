# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `678c8e8ec339f6c86679dfa33b5ee142afdb73e7`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27116842662`
- Synced at: `2026-06-08T05:25:49Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
