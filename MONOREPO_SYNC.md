# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `ac0ba4c5db7ebde125c8a6c8ef6c12e4ba889dcf`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25493583132`
- Synced at: `2026-05-07T12:02:59Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
