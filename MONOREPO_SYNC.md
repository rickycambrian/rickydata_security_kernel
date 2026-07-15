# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `62bd35b0d9a5e057cfffab6fde07e78ed7d54daf`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29437472023`
- Synced at: `2026-07-15T18:22:16Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
