/**
 * Phase 321. Brute-force protection on sensitive routes.
 * Off unless FULLSHIELD_EXPERIMENTAL_BRUTE=1.
 * A path is not sensitive because it contains the substring auth.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_BRUTE';
export const RULE = 'CONFIG-BRUTE-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type LimiterKey = 'username' | 'principal' | 'address' | 'constant' | 'other';

export interface Limiter {
  order: number;
  dominatesCredential: boolean;
  key: LimiterKey;
}

export interface SensitiveRoute {
  file: string;
  line: number;
  path: string;
  kind: 'login' | 'reset' | 'mfa' | 'other';
  routeOrder: number;
  limiter?: Limiter;
}

export interface BruteConfig {
  paths?: readonly string[];
}

export interface BruteFinding {
  ruleId: typeof RULE;
  severity: 'medium';
  confidence: 'medium';
  file: string;
  line: number;
  message: string;
  witness: string;
}

export function bruteFindings(routes: readonly SensitiveRoute[], config: BruteConfig = {}): BruteFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: BruteFinding[] = [];
  for (const route of routes) {
    const marked = route.kind === 'login' || route.kind === 'reset' || route.kind === 'mfa' || config.paths?.includes(route.path) === true;
    if (!marked) {
      continue;
    }
    const limiter = route.limiter;
    const later = limiter !== undefined && limiter.order >= route.routeOrder;
    if (limiter === undefined || later || !limiter.dominatesCredential) {
      findings.push({
        ruleId: RULE,
        severity: 'medium',
        confidence: 'medium',
        file: route.file,
        line: route.line,
        message: `Sensitive route ${route.path} has no dominating rate limit.`,
        witness: later ? 'registered-after' : 'missing-limiter',
      });
      continue;
    }
    if (limiter.key === 'constant' || limiter.key === 'other') {
      findings.push({
        ruleId: RULE,
        severity: 'medium',
        confidence: 'medium',
        file: route.file,
        line: route.line,
        message: `Sensitive route ${route.path} uses a shared bucket.`,
        witness: 'bucket is shared',
      });
    }
  }
  return findings;
}
