# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `39a57c9f83b38ff03bc1cb06e6bd49fbb1d9a0e9`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25588023175`
- Synced at: `2026-05-09T02:00:26Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
