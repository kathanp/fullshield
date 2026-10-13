import { makeFindingId, type Finding, type Severity } from '../../core/finding.js';

export function configFinding(
  ruleId: string,
  title: string,
  severity: Severity,
  file: string,
  message: string,
  remediation: string,
  line?: number,
): Finding {
  return {
    id: makeFindingId(ruleId, file, `${line ?? 0}|${title}`),
    ruleId,
    module: 'config',
    title,
    severity,
    confidence: 'medium',
    file,
    line,
    message,
    remediation,
  };
}
