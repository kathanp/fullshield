/**
 * Phase 346. Reviewed vulnerable-function database.
 * Off unless FULLSHIELD_EXPERIMENTAL_ADVDB=1.
 * Candidate rows are unreviewed. Rejected rows are never used. Reviewed promotion is not this phase.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_ADVDB';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type ReviewState = 'candidate' | 'reviewed' | 'rejected';

export interface SymbolRow {
  state: ReviewState;
  osvId: string;
  package: string;
  affectedExports: readonly string[];
  source: string;
  generic?: boolean;
}

export interface SymbolHit {
  osvId: string;
  packageName: string;
  exportName: string;
  label: 'unreviewed';
  confidence: 'medium' | 'high';
}

export function validateSymbolRow(row: SymbolRow): string[] {
  const errors: string[] = [];
  if (row.osvId.trim().length === 0) {
    errors.push('osvId');
  }
  if (row.package.trim().length === 0) {
    errors.push('package');
  }
  if (row.source.trim().length === 0) {
    errors.push('source');
  }
  if (row.affectedExports.length === 0) {
    errors.push('affectedExports');
  }
  for (const name of row.affectedExports) {
    const segments = name.split('.').filter((part) => part.length > 0);
    if (segments.length < 2 && row.generic !== true) {
      errors.push('export-path');
    }
  }
  if (row.state !== 'candidate' && row.state !== 'reviewed' && row.state !== 'rejected') {
    errors.push('state');
  }
  return errors;
}

export function reviewAuthorGuard(commit: { author: string; automation: boolean; from: ReviewState; to: ReviewState }): void {
  if (commit.automation && commit.to !== commit.from && (commit.to === 'reviewed' || commit.to === 'rejected')) {
    throw new TypeError('only a human commit may set reviewed or rejected');
  }
}

export function querySymbols(rows: readonly SymbolRow[], calls: readonly string[]): SymbolHit[] {
  if (!enabled()) {
    return [];
  }
  const hits: SymbolHit[] = [];
  for (const row of rows) {
    if (validateSymbolRow(row).length > 0 || row.state !== 'candidate') {
      continue;
    }
    for (const name of row.affectedExports) {
      const leaf = name.split('.').at(-1) ?? name;
      if (!calls.includes(name) && !calls.includes(leaf)) {
        continue;
      }
      hits.push({
        osvId: row.osvId,
        packageName: row.package,
        exportName: name,
        label: 'unreviewed',
        confidence: row.generic === true ? 'medium' : 'high',
      });
    }
  }
  return hits;
}
