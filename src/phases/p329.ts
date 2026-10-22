/**
 * Phase 329. Debug and docs routes.
 * Off unless FULLSHIELD_EXPERIMENTAL_DEBUGROUTE=1.
 * Catalog match is exact after mounts. /documentation does not match /docs.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_DEBUGROUTE';
export const RULE = 'CONFIG-DEBUG-ROUTE-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export const DEBUG_CATALOG = ['/metrics', '/playground', '/graphiql', '/graphql/playground', '/docs', '/swagger', '/debug'] as const;

export interface DebugRoute {
  file: string;
  line: number;
  fullPath: string;
  authKind: string;
  env?: 'development' | 'test' | 'production' | 'unknown';
  playgroundMount?: boolean;
}

export interface DebugFinding {
  ruleId: typeof RULE;
  severity: 'info' | 'medium';
  confidence: 'medium';
  file: string;
  line: number;
  message: string;
}

export function catalogMatch(fullPath: string): boolean {
  return DEBUG_CATALOG.some((entry) => fullPath === entry || fullPath.endsWith(entry));
}

export function debugFindings(routes: readonly DebugRoute[]): DebugFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: DebugFinding[] = [];
  for (const route of routes) {
    if (route.authKind !== 'none' || !(route.playgroundMount === true || catalogMatch(route.fullPath))) {
      continue;
    }
    const dev = route.env === 'development' || route.env === 'test';
    findings.push({
      ruleId: RULE,
      severity: dev ? 'info' : 'medium',
      confidence: 'medium',
      file: route.file,
      line: route.line,
      message: dev
        ? `${route.fullPath} is a debug route. Only in-app auth was considered.`
        : `${route.fullPath} is a debug route without auth. Only in-app auth was considered.`,
    });
  }
  return findings;
}
