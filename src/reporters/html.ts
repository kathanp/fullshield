import type { ScanResult } from '../core/engine.js';
import { SEVERITIES, type Finding } from '../core/finding.js';

function esc(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function location(finding: Finding): string {
  if (finding.file === undefined) return '(project)';
  return finding.line !== undefined ? `${finding.file}:${finding.line}` : finding.file;
}

/** Standalone HTML report. Finding text is escaped; secrets are already masked. */
export function renderHtmlReport(result: ScanResult): string {
  const sections: string[] = [];
  const bySeverityDesc = [...SEVERITIES].reverse();
  for (const severity of bySeverityDesc) {
    const group = result.findings.filter((f) => f.severity === severity);
    if (group.length === 0) continue;
    const items = group
      .map(
        (f) => `<article class="finding ${esc(severity)}">
  <h3>${esc(f.ruleId)} — ${esc(f.title)}</h3>
  <p class="where">${esc(location(f))}</p>
  <p>${esc(f.message)}</p>
  <p class="fix">Fix: ${esc(f.remediation)}</p>
</article>`,
      )
      .join('\n');
    sections.push(`<h2>${esc(severity)} (${group.length})</h2>\n${items}`);
  }
  if (sections.length === 0) {
    sections.push('<p>No findings.</p>');
  }
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>FullShield report</title>
  <style>
    body { font-family: sans-serif; max-width: 52rem; margin: 2rem auto; padding: 0 1rem; }
    .high, .critical { border-left: 4px solid #b91c1c; padding-left: 0.75rem; }
    .medium { border-left: 4px solid #b45309; padding-left: 0.75rem; }
    .low, .info { border-left: 4px solid #334155; padding-left: 0.75rem; }
    .where { color: #475569; font-family: monospace; }
  </style>
</head>
<body>
  <h1>FullShield report</h1>
  <p>Scanned ${result.metadata.filesScanned} files in ${result.metadata.durationMs}ms
     with FullShield v${esc(result.metadata.version)}.
     <strong>${result.summary.total} finding(s).</strong></p>
  ${sections.join('\n')}
</body>
</html>
`;
}
