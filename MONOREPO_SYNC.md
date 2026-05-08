# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `a25ae0b0bbaf9cf897bd4bbd2fcca876fccc64e7`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25535445631`
- Synced at: `2026-05-08T04:15:27Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
