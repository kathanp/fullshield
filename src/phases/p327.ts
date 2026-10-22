/**
 * Phase 327. GraphQL field authorization.
 * Off unless FULLSHIELD_EXPERIMENTAL_GQLAUTHZ=1.
 * A query-level check counts only when it dominates the resolver.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_GQLAUTHZ';
export const RULE = 'SAST-GQL-AUTHZ-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface GqlField {
  file: string;
  line: number;
  parent: string;
  field: string;
  parentPublic: boolean;
  authz?: string;
  directive?: string;
  directiveCatalog: boolean;
  reachesStore: boolean;
  sensitive: boolean;
  returnsLiteral: boolean;
  introspection: boolean;
  queryCheckDominates: boolean;
}

export interface GqlFinding {
  ruleId: typeof RULE;
  severity: 'medium';
  confidence: 'medium';
  file: string;
  line: number;
  message: string;
  witness: string;
}

const CATALOG = new Set(['auth', 'requiresAuth']);

export function gqlAuthzFindings(fields: readonly GqlField[]): GqlFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: GqlFinding[] = [];
  for (const field of fields) {
    if (!field.parentPublic || field.returnsLiteral || field.introspection || (!field.reachesStore && !field.sensitive)) {
      continue;
    }
    const name = field.directive?.startsWith('@') === true ? field.directive.slice(1) : (field.directive ?? '');
    const catalog = field.directiveCatalog && CATALOG.has(name);
    const guarded = (field.authz !== undefined && field.authz !== 'none') || catalog || field.queryCheckDominates;
    if (guarded) {
      continue;
    }
    findings.push({
      ruleId: RULE,
      severity: 'medium',
      confidence: 'medium',
      file: field.file,
      line: field.line,
      message: `Public ${field.parent}.${field.field} has no dominating authorization check.`,
      witness: field.directive ?? 'none',
    });
  }
  return findings;
}
