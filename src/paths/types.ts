import type { Finding, Severity } from '../core/finding.js';

export interface AttackPathEntry {
  method: string;
  path: string;
  auth: 'present' | 'absent';
}

export interface AttackPathStep {
  file: string;
  line?: number;
  note: string;
}

export interface AttackPath {
  kind: 'sink' | 'dependency' | 'secret';
  entry?: AttackPathEntry;
  steps: AttackPathStep[];
  sink: {
    id: string;
    ruleId: string;
    severity: Severity;
    file?: string;
    line?: number;
  };
  findingIds: string[];
}

export function sinkOf(finding: Finding): AttackPath['sink'] {
  return {
    id: finding.id,
    ruleId: finding.ruleId,
    severity: finding.severity,
    ...(finding.file !== undefined ? { file: finding.file } : {}),
    ...(finding.line !== undefined ? { line: finding.line } : {}),
  };
}
