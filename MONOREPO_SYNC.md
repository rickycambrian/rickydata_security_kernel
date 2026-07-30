# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `f12ca588a710ab27911fe2a9d341a63c7533b3fe`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30503219604`
- Synced at: `2026-07-30T01:44:25Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
