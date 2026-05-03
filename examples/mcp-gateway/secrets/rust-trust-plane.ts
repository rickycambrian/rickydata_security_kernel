import { existsSync } from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';
import type { SecretReleaseDecision, SecretReleaseGuardMode, SecretReleaseTrustSnapshot } from './release-guard.js';
import { log } from '../utils/logger.js';

export interface RustTrustPlaneMetrics {
  enabled: boolean;
  mode: 'shadow';
  version: string | null;
  binaryPath: string | null;
  decisionsTotal: number;
  mismatches: number;
  lastError: string | null;
  lastDecisionAt: string | null;
}

const metrics: RustTrustPlaneMetrics = {
  enabled: true,
  mode: 'shadow',
  version: null,
  binaryPath: null,
  decisionsTotal: 0,
  mismatches: 0,
  lastError: null,
  lastDecisionAt: null,
};

export function resetRustTrustPlaneMetricsForTests(): void {
  metrics.enabled = true;
  metrics.version = null;
  metrics.binaryPath = null;
  metrics.decisionsTotal = 0;
  metrics.mismatches = 0;
  metrics.lastError = null;
  metrics.lastDecisionAt = null;
}

export function getRustTrustPlaneMetrics(): RustTrustPlaneMetrics {
  return { ...metrics };
}

export function observeRustTrustDecision(
  snapshot: SecretReleaseTrustSnapshot,
  options: {
    mode: SecretReleaseGuardMode;
    enforceDegraded: boolean;
  },
  expected: SecretReleaseDecision,
): void {
  const mode = (process.env.TRUST_PLANE_ENABLED || 'shadow').toLowerCase();
  if (['false', '0', 'off', 'disabled'].includes(mode)) {
    metrics.enabled = false;
    return;
  }

  const binary = resolveTrustPlanePath();
  metrics.binaryPath = binary;
  metrics.enabled = true;
  metrics.decisionsTotal += 1;
  metrics.lastDecisionAt = new Date().toISOString();

  if (!binary || !existsSync(binary)) {
    metrics.lastError = binary ? `trust-plane binary not found at ${binary}` : 'trust-plane binary not configured';
    return;
  }

  const input = JSON.stringify({
    mode: options.mode,
    enforceDegraded: options.enforceDegraded,
    snapshot,
  });
  const result = spawnSync(binary, ['decide-secret-release'], {
    input,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
  });

  if (result.error) {
    metrics.lastError = result.error.message;
    return;
  }
  if (result.status !== 0) {
    metrics.lastError = (result.stderr || '').trim() || `trust-plane exited ${result.status}`;
    return;
  }

  try {
    const actual = JSON.parse(result.stdout || '{}') as Partial<SecretReleaseDecision> & { policyVersion?: string; version?: string };
    metrics.version = actual.version || actual.policyVersion || metrics.version;
    const matches = actual.allowed === expected.allowed
      && actual.wouldBlockIfFailClosed === expected.wouldBlockIfFailClosed
      && actual.state === expected.state
      && actual.reasonCode === expected.reasonCode;
    if (!matches) {
      metrics.mismatches += 1;
      metrics.lastError = 'rust trust-plane decision mismatch';
      log('warn', 'SecretReleaseGuard', 'Rust trust-plane shadow decision diverged', {
        state: snapshot.state,
        reasonCode: snapshot.reasonCode,
        mismatches: metrics.mismatches,
      });
    }
  } catch (err) {
    metrics.lastError = err instanceof Error ? err.message : String(err);
  }
}

function resolveTrustPlanePath(): string | null {
  const explicit = process.env.TRUST_PLANE_PATH?.trim();
  if (explicit) return explicit;
  const candidates = [
    '/usr/local/bin/trust-plane',
    path.resolve(process.cwd(), '../target/release/trust-plane'),
    path.resolve(process.cwd(), '../target/debug/trust-plane'),
    path.resolve(process.cwd(), '../../target/release/trust-plane'),
    path.resolve(process.cwd(), '../../target/debug/trust-plane'),
  ];
  return candidates.find((candidate) => existsSync(candidate)) || candidates[0];
}
