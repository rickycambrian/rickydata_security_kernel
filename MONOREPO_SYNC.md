# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `1daa09b4a8bbaa1c118721b2ecaddb20984dcf36`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27089534635`
- Synced at: `2026-06-07T10:41:22Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
