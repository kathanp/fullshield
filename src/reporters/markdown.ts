import type { ScanResult } from '../core/engine.js';
import { SEVERITIES, type Finding } from '../core/finding.js';

function location(finding: Finding): string {
  if (finding.file === undefined) return '(project)';
  return finding.line !== undefined ? `${finding.file}:${finding.line}` : finding.file;
}

/** Shareable Markdown report grouped by severity (highest first). */
export function renderMarkdownReport(result: ScanResult): string {
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
        lines.push(`- **Reachability:** \`${finding.reachability}\``);
      }
      lines.push(`- **Issue:** ${finding.message}`);
      lines.push(`- **Fix:** ${finding.remediation}`);
      if (finding.trace !== undefined && finding.trace.length > 0) {
        lines.push(
          `- **Trace:** ${finding.trace.map((s) => `\`${s.file}${s.line !== undefined ? `:${s.line}` : ''}\``).join(' → ')}`,
        );
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
