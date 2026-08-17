# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `ed9ec809949d2122143b6891f2e991f7ee18d6f9`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `32040431475`
- Synced at: `2026-08-17T16:33:47Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
