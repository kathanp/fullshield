/**
 * Phase 321. Brute-force protection on sensitive routes.
 * Off unless FULLSHIELD_EXPERIMENTAL_BRUTE=1.
 * A path is not sensitive because it contains the substring auth.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_BRUTE';
const RULE = 'CONFIG-BRUTE-001';

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

function sensitive(route: SensitiveRoute, config: BruteConfig): boolean {
  if (route.kind === 'login' || route.kind === 'reset' || route.kind === 'mfa') {
    return true;
  }
  return config.paths?.includes(route.path) === true;
}

function sharedBucket(key: LimiterKey): boolean {
  return key === 'constant' || key === 'other';
}

function bruteRow(route: SensitiveRoute, message: string, witness: string): BruteFinding {
  return { ruleId: RULE, severity: 'medium', confidence: 'medium', file: route.file, line: route.line, message, witness };
}

function bruteHit(route: SensitiveRoute): BruteFinding | undefined {
  const limiter = route.limiter;
  const later = limiter !== undefined && limiter.order >= route.routeOrder;
  if (limiter === undefined || later || !limiter.dominatesCredential) {
    const witness = later ? 'registered-after' : 'missing-limiter';
    return bruteRow(route, `Sensitive route ${route.path} has no dominating rate limit.`, witness);
  }
  if (sharedBucket(limiter.key)) {
    return bruteRow(route, `Sensitive route ${route.path} uses a shared bucket.`, 'bucket is shared');
  }
  return undefined;
}

export function bruteFindings(routes: readonly SensitiveRoute[], config: BruteConfig = {}): BruteFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: BruteFinding[] = [];
  for (const route of routes) {
    if (!sensitive(route, config)) {
      continue;
    }
    const hit = bruteHit(route);
    if (hit !== undefined) {
      findings.push(hit);
    }
  }
  return findings;
}
