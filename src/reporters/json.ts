import type { ScanResult } from '../core/engine.js';

/** Machine-readable report: full findings plus summary and scan metadata. */
export function renderJsonReport(result: ScanResult): string {
  return JSON.stringify(
    {
      findings: result.findings,
      summary: result.summary,
      metadata: result.metadata,
    },
    null,
    2,
  );
}
