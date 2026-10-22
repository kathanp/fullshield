/**
 * Phase 399. GraphQL depth and field-count cap.
 * Off unless FULLSHIELD_EXPERIMENTAL_GQLDEPTH=1.
 * Cost is 1 per field. Caps apply only when the hook is on.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_GQLDEPTH';
export const DEFAULT_DEPTH = 12;
export const DEFAULT_FIELDS = 200;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface GqlFinding {
  ruleId: 'SAST-GRAPHQL-001';
  severity: 'info';
  message: string;
}

export function countDocument(document: string): { depth: number; fields: number } {
  let depth = 0;
  let max = 0;
  let fields = 0;
  const tokens = document.replace(/#[^\n]*/g, '').match(/[{}]|[A-Za-z_][A-Za-z0-9_]*/g) ?? [];
  for (const token of tokens) {
    if (token === '{') {
      depth += 1;
      max = Math.max(max, depth);
      continue;
    }
    if (token === '}') {
      depth = Math.max(0, depth - 1);
      continue;
    }
    if (token === 'query' || token === 'mutation' || token === 'subscription') {
      continue;
    }
    fields += 1;
  }
  return { depth: max, fields };
}

export function graphqlGuard(
  document: string,
  config?: { depth?: number; fields?: number; exempt?: readonly string[] },
  persistedHash?: string,
): { reject: boolean; depth: number; fields: number } {
  const counted = countDocument(document);
  if (!enabled()) {
    return { reject: false, ...counted };
  }
  if (persistedHash !== undefined && config?.exempt?.includes(persistedHash)) {
    return { reject: false, ...counted };
  }
  const depthCap = config?.depth ?? DEFAULT_DEPTH;
  const fieldCap = config?.fields ?? DEFAULT_FIELDS;
  return { reject: counted.depth > depthCap || counted.fields > fieldCap, ...counted };
}

export function graphqlStatic(schemaSource: string, runtimeConfig: string | null): GqlFinding | null {
  if (!enabled()) {
    return null;
  }
  if (!/graphql/i.test(schemaSource)) {
    return null;
  }
  const hasCap = runtimeConfig !== null && /depth\s*:/.test(runtimeConfig) && /fields\s*:/.test(runtimeConfig);
  if (hasCap) {
    return null;
  }
  return {
    ruleId: 'SAST-GRAPHQL-001',
    severity: 'info',
    message: 'GraphQL route has no visible depth or field cap. This is info because the cap may live in another repo.',
  };
}
