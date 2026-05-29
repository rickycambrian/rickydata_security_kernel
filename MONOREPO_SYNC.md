# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `2a87ca31a96cb363ece6724a64508eb3358f1a80`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `26614593889`
- Synced at: `2026-05-29T03:06:10Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
