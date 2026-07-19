# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `65a3de6a116312aa3dc23ea7654a3eb00cbcb6a1`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `29698490935`
- Synced at: `2026-07-19T19:08:30Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
