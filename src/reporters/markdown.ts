import type { ScanResult } from '../core/engine.js';
import { SEVERITIES, type Finding } from '../core/finding.js';
import { redactScan } from './redact.js';

function location(finding: Finding): string {
  if (finding.file === undefined) return '(project)';
  return finding.line !== undefined ? `${finding.file}:${finding.line}` : finding.file;
}

/** Shareable Markdown report grouped by severity (highest first). */
export function renderMarkdownReport(input: ScanResult): string {
  const result = redactScan(input);
  const lines = [
    '# FullShield report',
    '',
    `Scanned ${result.metadata.filesScanned} files in ${result.metadata.durationMs}ms with FullShield v${result.metadata.version}.`,
    '',
    `**${result.summary.total} finding(s).**`,
    '',
  ];
  const bySeverityDesc = [...SEVERITIES].reverse();
  for (const severity of bySeverityDesc) {
    const group = result.findings.filter((f) => f.severity === severity);
    if (group.length === 0) continue;
    lines.push(`## ${severity} (${group.length})`, '');
    for (const finding of group) {
      lines.push(`### ${finding.ruleId} — ${finding.title}`);
      lines.push('');
      lines.push(`- **Where:** \`${location(finding)}\``);
      if (finding.reachability !== undefined) {
        const path =
          finding.dependencyPath !== undefined && finding.dependencyPath.length > 0
            ? ` (\`${finding.dependencyPath.join(' > ')}\`)`
            : '';
        lines.push(`- **Reachability:** \`${finding.reachability}\`${path}`);
      }
      lines.push(`- **Issue:** ${finding.message}`);
      lines.push(`- **Fix:** ${finding.remediation}`);
      if (finding.trace !== undefined && finding.trace.length > 0) {
        lines.push(
          `- **Trace:** ${finding.trace.map((s) => `\`${s.file}${s.line !== undefined ? `:${s.line}` : ''}\``).join(' → ')}`,
        );
      }
      if (finding.explanation !== undefined && finding.explanation.length > 0) {
        lines.push(`- **Explain:** ${finding.explanation}`);
      }
      lines.push('');
    }
  }
  if (result.summary.total === 0) {
    lines.push('No findings.');
    lines.push('');
  }
  return lines.join('\n');
}
