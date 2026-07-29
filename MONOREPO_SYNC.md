# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `3c7f63057b4179c4deb2136d10c3e3740d0b7c7e`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30434491548`
- Synced at: `2026-07-29T09:09:12Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
