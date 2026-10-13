import { readFile, writeFile } from 'node:fs/promises';

import type { Finding } from './finding.js';

export interface BaselineFile {
  version: 1;
  findings: Array<{ id: string; ruleId: string; file?: string; line?: number }>;
}

export async function readBaseline(path: string): Promise<BaselineFile | undefined> {
  try {
    const raw = JSON.parse(await readFile(path, 'utf8')) as BaselineFile;
    if (raw.version !== 1 || !Array.isArray(raw.findings)) return undefined;
    return raw;
  } catch {
    return undefined;
  }
}

export async function writeBaseline(path: string, findings: readonly Finding[]): Promise<void> {
  const doc: BaselineFile = {
    version: 1,
    findings: findings.map((f) => ({
      id: f.id,
      ruleId: f.ruleId,
      file: f.file,
      line: f.line,
    })),
  };
  await writeFile(path, `${JSON.stringify(doc, null, 2)}\n`, 'utf8');
}

export function applyBaseline(
  findings: readonly Finding[],
  baseline: BaselineFile | undefined,
): Finding[] {
  if (baseline === undefined) return [...findings];
  const known = new Set(baseline.findings.map((f) => f.id));
  return findings.filter((f) => !known.has(f.id));
}
