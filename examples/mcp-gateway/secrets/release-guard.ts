import { log } from '../utils/logger.js';
import {
  getRustTrustPlaneMetrics,
  observeRustTrustDecision,
  resetRustTrustPlaneMetricsForTests,
  type RustTrustPlaneMetrics,
} from './rust-trust-plane.js';
export type SecretReleaseTrustState = 'trusted' | 'degraded' | 'unavailable';

export type SecretReleaseGuardMode = 'permissive' | 'audit' | 'enforced';

export interface SecretReleaseDecision {
  allowed: boolean;
  wouldBlockIfFailClosed: boolean;
  state: SecretReleaseTrustState;
  reasonCode: string;
  detail: string | null;
}

export interface SecretReleaseTrustSnapshot {
  state: SecretReleaseTrustState;
  reasonCode?: string;
  detail?: string | null;
}

export interface SecretReleaseGuardMetrics {
  mode: 'permissive' | 'audit' | 'enforced';
  decisionsTotal: number;
  trustedCount: number;
  degradedCount: number;
  unavailableCount: number;
  guardErrorCount: number;
  wouldBlockTotal: number;
  wouldBlockDegradedCount: number;
  wouldBlockUnavailableCount: number;
  lastDecisionAt: string | null;
  lastState: SecretReleaseTrustState | null;
  lastReasonCode: string | null;
  lastDetail: string | null;
  lastWouldBlock: boolean | null;
  lastWouldBlockReasonCode: string | null;
  rustTrustPlane?: RustTrustPlaneMetrics;
}

type SecretReleaseTrustProvider = () => SecretReleaseTrustSnapshot | Promise<SecretReleaseTrustSnapshot>;

const LOG_COOLDOWN_MS = 60_000;
const lastWarnByReason = new Map<string, number>();

let provider: SecretReleaseTrustProvider = () => ({
  state: 'unavailable',
  reasonCode: 'trust_provider_not_configured',
  detail: null,
});

function isTrueEnv(value: string | undefined): boolean {
  return value?.trim().toLowerCase() === 'true';
}

function shouldEnforceDegradedTrustState(): boolean {
  return isTrueEnv(process.env.SECRET_RELEASE_GUARD_ENFORCE_DEGRADED);
}

function getGuardMode(): SecretReleaseGuardMode {
  const envMode = process.env.SECRET_RELEASE_GUARD_MODE?.toLowerCase();
  if (envMode === 'enforced') return 'enforced';
  if (envMode === 'permissive') return 'permissive';
  if (envMode === 'audit') return 'audit';
  // Default: audit in TEE mode, permissive otherwise
  return process.env.TEE_MODE === 'true' ? 'audit' : 'permissive';
}

const metrics: SecretReleaseGuardMetrics = {
  mode: getGuardMode(),
  decisionsTotal: 0,
  trustedCount: 0,
  degradedCount: 0,
  unavailableCount: 0,
  guardErrorCount: 0,
  wouldBlockTotal: 0,
  wouldBlockDegradedCount: 0,
  wouldBlockUnavailableCount: 0,
  lastDecisionAt: null,
  lastState: null,
  lastReasonCode: null,
  lastDetail: null,
  lastWouldBlock: null,
  lastWouldBlockReasonCode: null,
};

function shouldWarn(reasonCode: string): boolean {
  const now = Date.now();
  const last = lastWarnByReason.get(reasonCode) || 0;
  if (now - last < LOG_COOLDOWN_MS) {
    return false;
  }
  lastWarnByReason.set(reasonCode, now);
  return true;
}

function normalizeSnapshot(snapshot: SecretReleaseTrustSnapshot | null | undefined): SecretReleaseTrustSnapshot {
  if (!snapshot) {
    return {
      state: 'unavailable',
      reasonCode: 'trust_provider_empty_response',
      detail: null,
    };
  }

  if (snapshot.state !== 'trusted' && snapshot.state !== 'degraded' && snapshot.state !== 'unavailable') {
    return {
      state: 'unavailable',
      reasonCode: 'trust_provider_invalid_state',
      detail: `invalid state: ${String((snapshot as { state?: unknown }).state)}`,
    };
  }

  return {
    state: snapshot.state,
    reasonCode: snapshot.reasonCode || (snapshot.state === 'trusted' ? 'trusted' : 'degraded'),
    detail: snapshot.detail ?? null,
  };
}

function recordDecision(snapshot: SecretReleaseTrustSnapshot): SecretReleaseDecision {
  metrics.decisionsTotal += 1;
  metrics.lastDecisionAt = new Date().toISOString();
  metrics.lastState = snapshot.state;
  metrics.lastReasonCode = snapshot.reasonCode || null;
  metrics.lastDetail = snapshot.detail ?? null;

  const reasonCode = snapshot.reasonCode || (snapshot.state === 'trusted' ? 'trusted' : 'degraded');
  const mode = metrics.mode;
  const wouldBlockIfFailClosed = snapshot.state !== 'trusted';
  metrics.lastWouldBlock = wouldBlockIfFailClosed;
  metrics.lastWouldBlockReasonCode = wouldBlockIfFailClosed ? reasonCode : null;
  if (wouldBlockIfFailClosed) {
    metrics.wouldBlockTotal += 1;
  }

  if (snapshot.state === 'trusted') {
    metrics.trustedCount += 1;
    return {
      allowed: true,
      wouldBlockIfFailClosed,
      state: snapshot.state,
      reasonCode,
      detail: snapshot.detail ?? null,
    };
  }

  if (snapshot.state === 'unavailable') {
    metrics.unavailableCount += 1;
    metrics.wouldBlockUnavailableCount += 1;

    if (mode === 'enforced') {
      // Block the release
      return {
        allowed: false,
        wouldBlockIfFailClosed,
        state: snapshot.state,
        reasonCode,
        detail: snapshot.detail ?? null,
      };
    }

    if (mode === 'audit') {
      if (shouldWarn(reasonCode)) {
        log('error', 'SecretReleaseGuard', 'Audit: unavailable trust state, would block in enforced mode', {
          state: snapshot.state,
          reasonCode,
          detail: snapshot.detail ?? null,
        });
      }
    } else {
      // permissive
      if (shouldWarn(reasonCode)) {
        log('warn', 'SecretReleaseGuard', 'Permissive release under unavailable trust state', {
          state: snapshot.state,
          reasonCode,
          detail: snapshot.detail ?? null,
        });
      }
    }

    return {
      allowed: true,
      wouldBlockIfFailClosed,
      state: snapshot.state,
      reasonCode,
      detail: snapshot.detail ?? null,
    };
  }

  // degraded state
  metrics.degradedCount += 1;
  metrics.wouldBlockDegradedCount += 1;

  if (mode === 'enforced') {
    if (shouldEnforceDegradedTrustState()) {
      if (shouldWarn(reasonCode)) {
        log('error', 'SecretReleaseGuard', 'Enforced: degraded trust state blocked by fail-closed degraded policy', {
          state: snapshot.state,
          reasonCode,
          detail: snapshot.detail ?? null,
        });
      }
      return {
        allowed: false,
        wouldBlockIfFailClosed,
        state: snapshot.state,
        reasonCode,
        detail: snapshot.detail ?? null,
      };
    }

    if (shouldWarn(reasonCode)) {
      log('error', 'SecretReleaseGuard', 'Enforced: degraded trust state, allowing with error log', {
        state: snapshot.state,
        reasonCode,
        detail: snapshot.detail ?? null,
      });
    }
  } else if (mode === 'audit') {
    if (shouldWarn(reasonCode)) {
      log('error', 'SecretReleaseGuard', 'Audit: degraded trust state, would log error in enforced mode', {
        state: snapshot.state,
        reasonCode,
        detail: snapshot.detail ?? null,
      });
    }
  } else {
    // permissive
    if (shouldWarn(reasonCode)) {
      log('warn', 'SecretReleaseGuard', 'Permissive release under degraded trust state', {
        state: snapshot.state,
        reasonCode,
        detail: snapshot.detail ?? null,
      });
    }
  }

  return {
    allowed: true,
    wouldBlockIfFailClosed,
    state: snapshot.state,
    reasonCode,
    detail: snapshot.detail ?? null,
  };
}

export function setSecretReleaseTrustProvider(nextProvider: SecretReleaseTrustProvider): void {
  provider = nextProvider;
}

export function resetSecretReleaseGuardForTests(): void {
  provider = () => ({
    state: 'unavailable',
    reasonCode: 'trust_provider_not_configured',
    detail: null,
  });
  metrics.mode = getGuardMode();
  metrics.decisionsTotal = 0;
  metrics.trustedCount = 0;
  metrics.degradedCount = 0;
  metrics.unavailableCount = 0;
  metrics.guardErrorCount = 0;
  metrics.wouldBlockTotal = 0;
  metrics.wouldBlockDegradedCount = 0;
  metrics.wouldBlockUnavailableCount = 0;
  metrics.lastDecisionAt = null;
  metrics.lastState = null;
  metrics.lastReasonCode = null;
  metrics.lastDetail = null;
  metrics.lastWouldBlock = null;
  metrics.lastWouldBlockReasonCode = null;
  lastWarnByReason.clear();
  resetRustTrustPlaneMetricsForTests();
}

export function getSecretReleaseGuardMetrics(): SecretReleaseGuardMetrics {
  return { ...metrics, rustTrustPlane: getRustTrustPlaneMetrics() };
}

export async function observeSecretReleaseGuard(context: {
  walletAddress: string;
  serverId: string;
  source: 'mcp-vault';
}): Promise<SecretReleaseDecision> {
  try {
    const snapshot = normalizeSnapshot(await provider());
    const decision = recordDecision(snapshot);
    observeRustTrustDecision(snapshot, {
      mode: metrics.mode,
      enforceDegraded: shouldEnforceDegradedTrustState(),
    }, decision);
    return decision;
  } catch (err) {
    const reasonCode = 'trust_provider_error';
    metrics.decisionsTotal += 1;
    metrics.degradedCount += 1;
    metrics.guardErrorCount += 1;
    metrics.wouldBlockTotal += 1;
    metrics.wouldBlockDegradedCount += 1;
    metrics.lastDecisionAt = new Date().toISOString();
    metrics.lastState = 'degraded';
    metrics.lastReasonCode = reasonCode;
    metrics.lastDetail = err instanceof Error ? err.message : String(err);
    metrics.lastWouldBlock = true;
    metrics.lastWouldBlockReasonCode = reasonCode;

    const mode = metrics.mode;

    if (shouldWarn('trust_provider_error')) {
      if (mode === 'permissive') {
        log('warn', 'SecretReleaseGuard', 'Provider error; permissive release continues', {
          source: context.source,
          walletPrefix: context.walletAddress ? context.walletAddress.slice(0, 10) : '__anon__',
          serverId: context.serverId,
          error: metrics.lastDetail,
        });
      } else {
        log('error', 'SecretReleaseGuard', 'Provider error; degraded release continues', {
          source: context.source,
          walletPrefix: context.walletAddress ? context.walletAddress.slice(0, 10) : '__anon__',
          serverId: context.serverId,
          error: metrics.lastDetail,
        });
      }
    }

    const failClosedDegraded = mode === 'enforced' && shouldEnforceDegradedTrustState();
    // Provider errors are treated as degraded (not unavailable) unless fail-closed degraded
    // enforcement is explicitly enabled.
    return {
      allowed: !failClosedDegraded,
      wouldBlockIfFailClosed: true,
      state: 'degraded',
      reasonCode,
      detail: metrics.lastDetail,
    };
  }
}
