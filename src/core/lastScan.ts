import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { ScanResult } from './engine.js';

/** Persist a masked summary for `fullshield notify`. Never writes raw secrets. */
export async function writeLastScan(cwd: string, result: ScanResult): Promise<void> {
  const dir = join(cwd, '.fullshield');
  await mkdir(dir, { recursive: true });
  await writeFile(
    join(dir, 'last-scan.json'),
    JSON.stringify(
      {
        summary: result.summary,
        metadata: result.metadata,
        findings: result.findings.map((f) => ({
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
