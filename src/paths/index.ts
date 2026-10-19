import type { Finding } from '../core/finding.js';
import type { AttackPath } from '../core/engine.js';
import { priorityEnabled } from '../priority/index.js';

const SINK_RULES = new Set([
  'SAST-SQLI-001',
  'SAST-NOSQLI-001',
  'SAST-CMDI-001',
  'SAST-PATH-001',
  'SAST-SSRF-001',
  'SAST-XSS-001',
  'SAST-EVAL-001',
]);

/** Join findings that already exist. A path never creates a finding. */
export function attackPaths(findings: readonly Finding[]): AttackPath[] {
  const paths: AttackPath[] = [];
  for (const finding of findings) {
    if (!SINK_RULES.has(finding.ruleId)) continue;
    const snippet = finding.snippet ?? '';
    const auth = /requireAuth|authenticate|passport/.test(snippet) ? 'present' : 'absent';
    paths.push({
      auth,
      entry: { method: 'GET', path: finding.file ?? '/' },
      steps: finding.trace ?? [{ file: finding.file ?? '', line: finding.line, note: finding.ruleId }],
      findingId: finding.id,
      ruleId: finding.ruleId,
    });
  }
  paths.sort((a, b) => {
    if (priorityEnabled()) {
      const left = findings.find((finding) => finding.id === a.findingId)?.priority ?? 0;
      const right = findings.find((finding) => finding.id === b.findingId)?.priority ?? 0;
      if (right !== left) return right - left;
    }
    return a.ruleId.localeCompare(b.ruleId);
  });
  return paths.slice(0, 5);
}
