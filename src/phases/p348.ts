/**
 * Phase 348. Deprecation text linked to cached advisories.
 * Off unless FULLSHIELD_EXPERIMENTAL_DEPLINK=1.
 * Ids are copied from the string. A cache miss is unresolved and is not a vuln finding.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_DEPLINK';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface DeprecationInput {
  packageName: string;
  ruleId: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  deprecated?: string;
}

export interface DeprecationOutput extends DeprecationInput {
  linkedAdvisory?: string;
}

export function linkDeprecations(
  rows: readonly DeprecationInput[],
  cache: ReadonlyMap<string, readonly string[]>,
): DeprecationOutput[] {
  if (!enabled()) {
    return rows.map((row) => ({ ...row }));
  }
  return rows.map((row) => {
    const text = row.deprecated ?? '';
    const ids = [...text.matchAll(/GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|CVE-\d{4}-\d+|MAL-\d{4}-\d+/gi)].map((match) => match[0]);
    if (ids.length === 0) {
      return { ...row };
    }
    const known = new Set((cache.get(row.packageName) ?? []).map((id) => id.toUpperCase()));
    const first = ids[0] ?? '';
    const linked = known.has(first.toUpperCase()) ? first : 'unresolved';
    return { ...row, linkedAdvisory: linked, severity: row.severity };
  });
}
