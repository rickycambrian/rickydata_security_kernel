# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `2036a3f8e2c854ccfa2a880c0beba599cd6bcfad`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31016683498`
- Synced at: `2026-08-05T15:19:37Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
