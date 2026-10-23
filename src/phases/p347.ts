/**
 * Phase 347. Patch-diff candidate symbols.
 * Off unless FULLSHIELD_EXPERIMENTAL_PATCHDIFF=1.
 * Flag off fails with FS-E347 and does not read the diff. Rows are candidate only.
 */

import type { SymbolRow } from './p346.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PATCHDIFF';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export class PatchDiffError extends Error {
  readonly code = 'FS-E347';
  constructor(message: string) {
    super(`FS-E347 ${message}`);
    this.name = 'PatchDiffError';
  }
}

export interface CandidateRow {
  state: 'candidate';
  packageName: string;
  exportName: string;
  source: string;
}

export interface HunkWrite {
  exitCode: number;
  rows: SymbolRow[];
}

function addedLines(hunk: string): string[] {
  return hunk.split('\n').filter((line) => line.startsWith('+') && !line.startsWith('+++')).map((line) => line.slice(1));
}

function contextAndAdded(hunk: string): string[] {
  return hunk
    .split('\n')
    .filter((line) => (line.startsWith('+') && !line.startsWith('+++')) || (line.startsWith(' ') && !line.startsWith('+++')))
    .map((line) => line.slice(1));
}

function commentOnly(lines: readonly string[]): boolean {
  return lines.length > 0 && lines.every((line) => line.trim().length === 0 || line.trim().startsWith('//') || line.trim().startsWith('/*') || line.trim().startsWith('*'));
}

export function candidatesFromDiff(readDiff: () => string, sourcePath: string, packageName: string): CandidateRow[] {
  if (!enabled()) {
    throw new PatchDiffError('FULLSHIELD_EXPERIMENTAL_PATCHDIFF');
  }
  const diff = readDiff();
  const added = addedLines(diff);
  if (commentOnly(added)) {
    return [];
  }
  const names = new Set<string>();
  const body = contextAndAdded(diff);
  let current = '';
  for (const line of body) {
    const fn = /function\s+([A-Za-z0-9_]+)/.exec(line)?.[1];
    if (fn !== undefined) {
      current = fn;
    }
    if (added.includes(line) && current.length > 0 && !line.trim().startsWith('//')) {
      names.add(current);
    }
    const exported = /exports\.([A-Za-z0-9_]+)/.exec(line)?.[1];
    if (exported !== undefined && added.includes(line)) {
      names.add(exported);
    }
  }
  return [...names].sort().map((exportName) => ({ state: 'candidate', packageName, exportName, source: sourcePath }));
}

export function writeCandidates(existing: readonly SymbolRow[], incoming: readonly CandidateRow[], write: boolean): HunkWrite {
  if (!enabled()) {
    throw new PatchDiffError('FULLSHIELD_EXPERIMENTAL_PATCHDIFF');
  }
  if (!write) {
    return { exitCode: 0, rows: [...existing] };
  }
  for (const row of incoming) {
    const prior = existing.find((item) => item.package === row.packageName && item.affectedExports.includes(`${row.packageName}.${row.exportName}`));
    if (prior?.state === 'reviewed') {
      return { exitCode: 1, rows: [...existing] };
    }
  }
  const next = existing.map((row) => ({ ...row }));
  for (const row of incoming) {
    next.push({
      state: 'candidate',
      osvId: '',
      package: row.packageName,
      affectedExports: [`${row.packageName}.${row.exportName}`],
      source: row.source,
    });
  }
  return { exitCode: 0, rows: next };
}
