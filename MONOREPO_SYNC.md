# Monorepo Security Evidence Sync

This repository owns the canonical `@rickydata/security-kernel` package source under `src/`.
Gateway-specific wrappers and Rust trust-plane helpers are mirrored under `examples/` so auditors can
inspect how the package is used by production gateways without mixing gateway-only imports into the npm package.

- Source monorepo commit: `8075800400e94d4d560c9afdfb0ef94ff2c57a3d`
- Source workflow: `Deploy Agent Gateway to TEE`
- Source workflow run: `25555031490`
- Synced at: `2026-05-08T12:55:56Z`

Mirrored paths:
- `examples/mcp-agent-gateway/secrets/`
- `examples/mcp-gateway/secrets/`
- `examples/rust-trust-plane/`

KFDB TEE evidence is published separately by the `knowledgeflow_db` `TEE Security Lab` workflow:
- Current bundle: `evidence/latest.json`
- Historical bundles: `evidence/runs/*.json`
- Schema: `evidence/schema.json`
