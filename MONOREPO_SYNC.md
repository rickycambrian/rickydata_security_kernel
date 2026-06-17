# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `2f8e4a6b17f902b9468b18678ffbbd28bff72e7a`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27655864043`
- Synced at: `2026-06-17T01:02:20Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
