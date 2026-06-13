# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `4b3e04407d33a4cd7e70c1193c2c796f4b7fc751`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27450104218`
- Synced at: `2026-06-13T02:36:54Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
