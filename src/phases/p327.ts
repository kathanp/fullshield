/**
 * Phase 327. GraphQL field authorization.
 * Off unless FULLSHIELD_EXPERIMENTAL_GQLAUTHZ=1.
 * A query-level check counts only when it dominates the resolver.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_GQLAUTHZ';
const RULE = 'SAST-GQL-AUTHZ-001';

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

function inScope(field: GqlField): boolean {
  if (!field.parentPublic || field.returnsLiteral || field.introspection) {
    return false;
  }
  return field.reachesStore || field.sensitive;
}

function directiveName(field: GqlField): string {
  if (field.directive?.startsWith('@') === true) {
    return field.directive.slice(1);
  }
  return field.directive ?? '';
}

function guarded(field: GqlField): boolean {
  if (field.authz !== undefined && field.authz !== 'none') {
    return true;
  }
  if (field.directiveCatalog && CATALOG.has(directiveName(field))) {
    return true;
  }
  return field.queryCheckDominates;
}

function authzHit(field: GqlField): GqlFinding | undefined {
  if (!inScope(field) || guarded(field)) {
    return undefined;
  }
  return {
    ruleId: RULE,
    severity: 'medium',
    confidence: 'medium',
    file: field.file,
    line: field.line,
    message: `Public ${field.parent}.${field.field} has no dominating authorization check.`,
    witness: field.directive ?? 'none',
  };
}

export function gqlAuthzFindings(fields: readonly GqlField[]): GqlFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: GqlFinding[] = [];
  for (const field of fields) {
    const hit = authzHit(field);
    if (hit !== undefined) {
      findings.push(hit);
    }
  }
  return findings;
}
