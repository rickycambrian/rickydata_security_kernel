# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `7ebbaaa61c8c3583fd5c48072755b4542785d28c`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27737600458`
- Synced at: `2026-06-18T05:30:44Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
