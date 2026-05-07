# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `91dd4b4599655e5a1ad5bdc3ab423cd42304393c`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25473564683`
- Synced at: `2026-05-07T03:35:01Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
