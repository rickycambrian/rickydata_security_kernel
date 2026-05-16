# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `03021be911dfd7b3e3778b303756cacaf4f13b72`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25950654366`
- Synced at: `2026-05-16T03:28:40Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
