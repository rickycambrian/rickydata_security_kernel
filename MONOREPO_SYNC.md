# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `a4862231a11ff13a35d595f2a0e7a7c83674a9e1`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `30864597801`
- Synced at: `2026-08-04T00:44:41Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
