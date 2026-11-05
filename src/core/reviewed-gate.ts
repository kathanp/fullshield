import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { Finding } from './finding.js';

export interface ReviewedPrecision {
  ruleId: string;
  precision: number;
  n: number;
  reviewer: string;
}

/** Rows without a reviewer are ignored. A rule below 80% with n >= 5 does not fail the gate. */
export function reviewedPrecisionRows(raw: unknown): ReviewedPrecision[] {
  if (typeof raw !== 'object' || raw === null || !('rows' in raw) || !Array.isArray(raw.rows)) {return [];}
  const rows: ReviewedPrecision[] = [];
  for (const item of raw.rows) {
    if (typeof item !== 'object' || item === null) {continue;}
    const row = item as Record<string, unknown>;
    if (typeof row.ruleId !== 'string' || typeof row.reviewer !== 'string' || row.reviewer.length === 0) {continue;}
    if (typeof row.precision !== 'number' || typeof row.n !== 'number') {continue;}
    rows.push({ ruleId: row.ruleId, precision: row.precision, n: row.n, reviewer: row.reviewer });
  }
  return rows;
}

export function applyReviewedPrecision(findings: readonly Finding[], rows: readonly ReviewedPrecision[]): Finding[] {
  const quiet = new Set(rows.filter((row) => row.n >= 5 && row.precision < 0.8).map((row) => row.ruleId));
  if (quiet.size === 0) {return [...findings];}
  return findings.map((finding) => quiet.has(finding.ruleId) ? { ...finding, gate: false } : finding);
}

export async function readReviewedPrecision(cwd: string): Promise<ReviewedPrecision[]> {
  try {
    const text = await readFile(join(cwd, '.fullshield', 'precision.json'), 'utf8');
    return reviewedPrecisionRows(JSON.parse(text));
  } catch {
    return [];
  }
}
