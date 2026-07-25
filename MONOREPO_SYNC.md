# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `ac261b51efe52ef6c9dce0d38ffc4efcc9f001e4`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30167759334`
- Synced at: `2026-07-25T18:23:09Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
