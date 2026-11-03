import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { Finding } from '../../core/finding.js';

export interface VulnFunctionRow {
  osvId: string;
  package: string;
  symbol: string;
  source: string;
}

/** Reviewed rows only. A row without a citation is ignored. */
export function reviewedVulnFunctions(raw: unknown): VulnFunctionRow[] {
  if (typeof raw !== 'object' || raw === null || !('rows' in raw) || !Array.isArray(raw.rows)) {
    return [];
  }
  const rows: VulnFunctionRow[] = [];
  for (const item of raw.rows) {
    if (typeof item !== 'object' || item === null) {continue;}
    const row = item as Record<string, unknown>;
    if (row.reviewed !== true) {continue;}
    if (typeof row.osvId !== 'string' || typeof row.package !== 'string') {continue;}
    if (typeof row.symbol !== 'string' || typeof row.source !== 'string' || row.source.length === 0) {continue;}
    rows.push({ osvId: row.osvId, package: row.package, symbol: row.symbol, source: row.source });
  }
  return rows;
}

export function scannerRoot(): string {
  return fileURLToPath(new URL('../../../', import.meta.url));
}

/** Attach a reviewed symbol only when the finding names that advisory. */
export function symbolsForReviewedRows(
  findings: readonly Finding[],
  rows: readonly VulnFunctionRow[],
): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const finding of findings) {
    if (finding.ruleId !== 'DEPS-VULN-001') {continue;}
    const text = `${finding.message} ${(finding.references ?? []).join(' ')}`;
    for (const row of rows) {
      if (!text.includes(row.osvId)) {continue;}
      const list = out.get(finding.id) ?? [];
      list.push(row.symbol);
      out.set(finding.id, list);
    }
  }
  return out;
}

export async function mergeReviewedSymbols(
  findings: readonly Finding[],
  symbols: ReadonlyMap<string, readonly string[]>,
): Promise<Map<string, readonly string[]>> {
  const extra = symbolsForReviewedRows(findings, await loadVulnFunctions(scannerRoot()));
  const merged = new Map<string, readonly string[]>(symbols);
  for (const [id, names] of extra) {
    merged.set(id, [...(merged.get(id) ?? []), ...names]);
  }
  return merged;
}

export async function loadVulnFunctions(root: string): Promise<VulnFunctionRow[]> {
  try {
    const text = await readFile(join(root, 'models', 'vuln-functions.json'), 'utf8');
    return reviewedVulnFunctions(JSON.parse(text));
  } catch {
    return [];
  }
}
