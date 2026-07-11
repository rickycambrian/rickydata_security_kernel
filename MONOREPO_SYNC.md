# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `7a86dbca9ccefcd4bad6149ce7c45f3ac5d3428c`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29132044777`
- Synced at: `2026-07-11T01:04:00Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
