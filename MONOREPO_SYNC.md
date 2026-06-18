# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `dde96cf5d75fccce3f54d8203ad65c45794d3c3c`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `27779506064`
- Synced at: `2026-06-18T18:58:49Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`
