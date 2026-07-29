# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `87c4f8d6583ff6732074d6d9764c7bd5a90cd208`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30412771896`
- Synced at: `2026-07-29T01:30:33Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
