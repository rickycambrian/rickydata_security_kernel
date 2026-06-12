# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `aa21adb47df41417315428c1dff6cf62ae982a4a`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27447506125`
- Synced at: `2026-06-12T23:24:52Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
