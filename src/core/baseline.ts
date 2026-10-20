import { readFile, writeFile } from 'node:fs/promises';

import type { Finding } from './finding.js';

export interface Suppression {
  ruleId: string;
  file?: string;
  owner: string;
  reason: string;
  /** ISO date (`YYYY-MM-DD`) or datetime. */
  expires: string;
}

export interface BaselineFile {
  version: 1;
  findings: Array<{ id: string; ruleId: string; file?: string; line?: number }>;
  suppressions?: Suppression[];
}

function isIsoDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}(T[\d:.+\-Z]+)?$/.test(value)) {return false;}
  return Number.isFinite(Date.parse(value));
}

function expiresAtMs(expires: string): number {
  if (/^\d{4}-\d{2}-\d{2}$/.test(expires)) {return Date.parse(`${expires}T23:59:59.999Z`);}
  return Date.parse(expires);
}

function validSuppression(value: unknown): Suppression | undefined {
  if (typeof value !== 'object' || value === null) {return undefined;}
  const row = value as Partial<Suppression>;
  if (typeof row.ruleId !== 'string' || row.ruleId.length === 0) {return undefined;}
  if (typeof row.owner !== 'string' || row.owner.length === 0) {return undefined;}
  if (typeof row.reason !== 'string' || row.reason.length === 0) {return undefined;}
  if (typeof row.expires !== 'string' || !isIsoDate(row.expires)) {return undefined;}
  const file = row.file === undefined ? undefined : row.file.replace(/\\/g, '/');
  if (row.file !== undefined && (typeof row.file !== 'string' || row.file.length === 0)) {return undefined;}
  return { ruleId: row.ruleId, file, owner: row.owner, reason: row.reason, expires: row.expires };
}

export async function readBaseline(path: string): Promise<BaselineFile | undefined> {
  try {
    const raw = JSON.parse(await readFile(path, 'utf8')) as BaselineFile;
    if (raw.version !== 1 || !Array.isArray(raw.findings)) {return undefined;}
    if (raw.suppressions !== undefined && !Array.isArray(raw.suppressions)) {return undefined;}
    return raw;
  } catch {
    return undefined;
  }
}

export async function writeBaseline(path: string, findings: readonly Finding[]): Promise<void> {
  const existing = await readBaseline(path);
  const doc: BaselineFile = {
    version: 1,
    findings: findings.map((f) => ({
      id: f.id,
      ruleId: f.ruleId,
      file: f.file,
      line: f.line,
    })),
    ...(existing?.suppressions !== undefined ? { suppressions: existing.suppressions } : {}),
  };
  await writeFile(path, `${JSON.stringify(doc, null, 2)}\n`, 'utf8');
}

export function applyBaseline(
  findings: readonly Finding[],
  baseline: BaselineFile | undefined,
): Finding[] {
  if (baseline === undefined) {return [...findings];}
  const known = new Set(baseline.findings.map((f) => f.id));
  return findings.filter((f) => !known.has(f.id));
}

export interface SuppressionResult {
  findings: Finding[];
  errors: string[];
}

/**
 * Drop findings covered by a suppression that has owner, reason, and a future expiry.
 * A bad or expired row does not hide a finding. Its error is returned for CI.
 */
export function applySuppressions(
  findings: readonly Finding[],
  rows: readonly unknown[] | undefined,
  now = new Date(),
): SuppressionResult {
  if (rows === undefined || rows.length === 0) {return { findings: [...findings], errors: [] };}
  const errors: string[] = [];
  const active: Suppression[] = [];
  rows.forEach((row, index) => {
    const parsed = validSuppression(row);
    if (parsed === undefined) {
      errors.push(`suppression ${index + 1} needs ruleId, owner, reason, and an ISO expires date`);
      return;
    }
    if (expiresAtMs(parsed.expires) < now.getTime()) {
      errors.push(
        `suppression for ${parsed.ruleId} expired on ${parsed.expires} (owner: ${parsed.owner}); renew or remove it`,
      );
      return;
    }
    active.push(parsed);
  });
  const kept = findings.filter((finding) => {
    const file = (finding.file ?? '').replace(/\\/g, '/');
    return !active.some((row) => row.ruleId === finding.ruleId && (row.file === undefined || row.file === file));
  });
  return { findings: kept, errors };
}
