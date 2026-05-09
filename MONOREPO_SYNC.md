# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `073870525dc9c330b01cb76298c0dd73c3e7d2a1`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25591507107`
- Synced at: `2026-05-09T04:43:07Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
