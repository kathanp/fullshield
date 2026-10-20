import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { ScanResult } from './engine.js';

/** Persist a masked summary for `fullshield notify`. Never writes raw secrets. */
export async function writeLastScan(cwd: string, result: ScanResult): Promise<void> {
  // Do not mutate packaged fixtures; parallel tests copy them for watch/e2e.
  if (/(?:^|[/\\])test[/\\]fixtures[/\\]/.test(cwd)) {return;}
  const dir = join(cwd, '.fullshield');
  await mkdir(dir, { recursive: true });
  await writeFile(
    join(dir, 'last-scan.json'),
    JSON.stringify(
      {
        summary: result.summary,
        metadata: result.metadata,
        findings: result.findings.map((f) => ({
          id: f.id,
          ruleId: f.ruleId,
          severity: f.severity,
          file: f.file,
          line: f.line,
          message: f.message,
          snippet: f.snippet,
        })),
      },
      null,
      2,
    ),
    'utf8',
  );
}

export async function readLastScanIds(cwd: string): Promise<Set<string>> {
  try {
    const raw = JSON.parse(await readFile(join(cwd, '.fullshield', 'last-scan.json'), 'utf8')) as {
      findings?: Array<{ id?: string; ruleId?: string; snippet?: string }>;
    };
    const ids = new Set<string>();
    for (const f of raw.findings ?? []) {
      if (typeof f.id === 'string' && f.id.length > 0) {ids.add(f.id);}
    }
    return ids;
  } catch {
    return new Set();
  }
}
