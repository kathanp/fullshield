/**
 * Phase 322. CSRF and cookie-authenticated mutations.
 * Off unless FULLSHIELD_EXPERIMENTAL_CSRF2=1.
 * SameSite is recorded and is not a substitute for a dominating check.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CSRF2';
const RULE = 'CONFIG-CSRF-001';

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

function headerKnown(route: CsrfRoute, config: CsrfConfig): boolean {
  if (route.customHeader === undefined) {
    return false;
  }
  if (config.headerNames === undefined) {
    return true;
  }
  return config.headerNames.includes(route.customHeader);
}

function csrfChecked(route: CsrfRoute, known: boolean): boolean {
  return route.catalogCsrf || route.tokenCompare || (known && route.headerDominates);
}

function catalogNote(route: CsrfRoute, known: boolean): string {
  if (route.customHeader !== undefined && !known) {
    return ' The check was not in the catalog.';
  }
  return '';
}

function csrfHit(route: CsrfRoute, config: CsrfConfig, methods: ReadonlySet<string>): CsrfFinding | undefined {
  if (!methods.has(route.method.toUpperCase()) || !cookieBacked(route)) {
    return undefined;
  }
  const known = headerKnown(route, config);
  if (csrfChecked(route, known)) {
    return undefined;
  }
  return {
    ruleId: RULE,
    severity: 'high',
    confidence: 'medium',
    file: route.file,
    line: route.line,
    message: `Cookie-authenticated ${route.method} ${route.path} has no dominating CSRF check.${catalogNote(route, known)}`,
    witness: `sameSite=${route.sameSite ?? 'absent'}`,
  };
}

export function csrfFindings(routes: readonly CsrfRoute[], config: CsrfConfig = {}): CsrfFinding[] {
  if (!enabled()) {
    return [];
  }
  const methods = new Set<string>([...MUTATIONS, ...(config.methods ?? []).map((method) => method.toUpperCase())]);
  const findings: CsrfFinding[] = [];
  for (const route of routes) {
    const hit = csrfHit(route, config, methods);
    if (hit !== undefined) {
      findings.push(hit);
    }
  }
  return findings;
}
