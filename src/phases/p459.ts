/**
 * Phase 459. Proxy header pairing.
 * Off unless FULLSHIELD_EXPERIMENTAL_PROXYPAIR=1.
 * Flag off: the baseline finding list is returned unchanged.
 * A finding is emitted only when both the proxy file and the app setting exist.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PROXYPAIR';
export const PROXY_RULE = 'CONFIG-PROXY-001';
export const PROXY_SENTENCE = 'only the in-repo proxy was compared';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface PhaseFinding {
  ruleId: string;
  severity: 'high';
  file: string;
  line: number;
  message: string;
}

function trustsProxy(source: string): boolean {
  return /trust\s+proxy['"]?\s*,\s*true/.test(source) || /trust proxy['"]?\s*,\s*1\b/.test(source) || /['"]trust proxy['"]\s*,\s*true/.test(source);
}

export function scanProxyPair(source: string | null, nginx: string | null, file = 'nginx.conf', baseline: readonly PhaseFinding[] = []): PhaseFinding[] {
  if (!enabled()) {
    return [...baseline];
  }
  if (source === null || nginx === null) {
    return [...baseline];
  }
  if (!trustsProxy(source)) {
    return [...baseline];
  }
  if (!nginx.includes('$proxy_add_x_forwarded_for')) {
    return [...baseline];
  }
  const line = nginx.split(/\r?\n/).findIndex((row) => row.includes('$proxy_add_x_forwarded_for')) + 1;
  return [
    ...baseline,
    {
      ruleId: PROXY_RULE,
      severity: 'high',
      file,
      line: line === 0 ? 1 : line,
      message: `CONFIG-PROXY-001 client can prepend X-Forwarded-For; ${PROXY_SENTENCE}`,
    },
  ];
}
