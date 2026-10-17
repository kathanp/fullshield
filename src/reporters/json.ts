import type { ScanResult } from '../core/engine.js';
import type { Finding } from '../core/finding.js';
import { redactFinding } from './redact.js';

/** 0.1.0 never publishes an AI verdict on the explain path. */
function publicFinding(finding: Finding): Finding {
  const copy = redactFinding(finding);
  delete copy.aiVerdict;
  delete copy.exploitScenario;
  delete copy.aiReasoning;
  return copy;
}

/** Machine-readable report: full findings plus summary and scan metadata. */
export function renderJsonReport(result: ScanResult): string {
  return JSON.stringify(
    {
      findings: result.findings.map(publicFinding),
      summary: result.summary,
      metadata: result.metadata,
    },
    null,
    2,
  );
}
