# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `890b2e3ca7c1aa45eb180c820e23c326ea5b4a88`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `31331523159`
- Synced at: `2026-08-09T20:00:26Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
