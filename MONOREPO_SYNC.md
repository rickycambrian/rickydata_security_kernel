# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `40b84e45ef6fd629e33ac5b95a0b35749b099529`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25590323437`
- Synced at: `2026-05-09T03:57:05Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
