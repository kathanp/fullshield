/** Phase 260. Unreviewed rows are used only under the flag and stay labeled unreviewed. */
export const ADVSYMBOLS_FLAG = 'FULLSHIELD_EXPERIMENTAL_ADVSYMBOLS';

export function advisorySymbolsEnabled(): boolean {
  return process.env[ADVSYMBOLS_FLAG] === '1';
}

export interface AdvisorySymbolRow {
  osvId: string;
  package: string;
  affectedExports: readonly string[];
  source: string;
  reviewed: boolean;
}

export interface SymbolReach {
  reachability: 'symbol-not-called' | 'symbol-reachable';
  label: 'unreviewed' | 'reviewed';
  osvId: string;
}

export function loadAdvisorySymbols(raw: unknown): AdvisorySymbolRow[] {
  if (typeof raw !== 'object' || raw === null || !('rows' in raw) || !Array.isArray(raw.rows)) {
    throw new Error('symbols must be an object with rows');
  }
  return raw.rows.map((row) => {
    if (typeof row !== 'object' || row === null) {throw new Error('missing source');}
    const record = row as Record<string, unknown>;
    if (typeof record.source !== 'string' || record.source.length === 0) {throw new Error('missing source');}
    if (typeof record.osvId !== 'string' || typeof record.package !== 'string' || !Array.isArray(record.affectedExports)) {
      throw new Error('missing source');
    }
    const exports = record.affectedExports.filter((name): name is string => typeof name === 'string');
    return {
      osvId: record.osvId,
      package: record.package,
      affectedExports: exports,
      source: record.source,
      reviewed: record.reviewed === true,
    };
  });
}

/** Imported package whose affected export is never called. Does not invent a downgrade. */
export function symbolReach(row: AdvisorySymbolRow, calledExports: readonly string[]): SymbolReach | undefined {
  if (!advisorySymbolsEnabled()) {return undefined;}
  const called = row.affectedExports.some((name) => calledExports.includes(name));
  return {
    reachability: called ? 'symbol-reachable' : 'symbol-not-called',
    label: row.reviewed ? 'reviewed' : 'unreviewed',
    osvId: row.osvId,
  };
}
