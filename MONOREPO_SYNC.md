# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `0a5142e335861cc75b3f94effdebc8ba73322f55`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25713400979`
- Synced at: `2026-05-12T04:54:52Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
