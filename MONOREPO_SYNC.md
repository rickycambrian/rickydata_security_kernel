# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `e2a8889817ef28b61be01de7f66b281e59a0d58d`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31447455704`
- Synced at: `2026-08-11T01:31:44Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
