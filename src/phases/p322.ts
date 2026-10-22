/**
 * Phase 322. CSRF and cookie-authenticated mutations.
 * Off unless FULLSHIELD_EXPERIMENTAL_CSRF2=1.
 * SameSite is recorded and is not a substitute for a dominating check.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CSRF2';
export const RULE = 'CONFIG-CSRF-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface CsrfRoute {
  file: string;
  line: number;
  method: string;
  path: string;
  authKind: string;
  passportSession?: boolean;
  sameSite?: 'lax' | 'strict' | 'none';
  catalogCsrf: boolean;
  tokenCompare: boolean;
  customHeader?: string;
  headerDominates: boolean;
}

export interface CsrfConfig {
  methods?: readonly string[];
  headerNames?: readonly string[];
}

export interface CsrfFinding {
  ruleId: typeof RULE;
  severity: 'high';
  confidence: 'medium';
  file: string;
  line: number;
  message: string;
  witness: string;
}

const MUTATIONS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function cookieBacked(route: CsrfRoute): boolean {
  if (route.authKind === 'session') {
    return true;
  }
  return route.authKind.startsWith('passport:') && route.passportSession !== false;
}

export function csrfFindings(routes: readonly CsrfRoute[], config: CsrfConfig = {}): CsrfFinding[] {
  if (!enabled()) {
    return [];
  }
  const methods = new Set<string>([...MUTATIONS, ...(config.methods ?? []).map((method) => method.toUpperCase())]);
  const findings: CsrfFinding[] = [];
  for (const route of routes) {
    if (!methods.has(route.method.toUpperCase()) || !cookieBacked(route)) {
      continue;
    }
    const headerKnown = route.customHeader !== undefined && (config.headerNames === undefined || config.headerNames.includes(route.customHeader));
    const checked = route.catalogCsrf || route.tokenCompare || (headerKnown && route.headerDominates);
    if (checked) {
      continue;
    }
    const catalogNote = route.customHeader !== undefined && !headerKnown ? ' The check was not in the catalog.' : '';
    findings.push({
      ruleId: RULE,
      severity: 'high',
      confidence: 'medium',
      file: route.file,
      line: route.line,
      message: `Cookie-authenticated ${route.method} ${route.path} has no dominating CSRF check.${catalogNote}`,
      witness: `sameSite=${route.sameSite ?? 'absent'}`,
    });
  }
  return findings;
}
