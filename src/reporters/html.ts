import type { ScanResult } from '../core/engine.js';
import { SEVERITIES, type Finding } from '../core/finding.js';
import { taintEdgeLine } from '../modules/sast/parity.js';
import type { AttackPath } from '../paths/types.js';
import { redactScan } from './redact.js';

function esc(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderPaths(paths: readonly AttackPath[]): string {
  if (paths.length === 0) {return '<section id="paths"><h2>Paths</h2><p>No attack paths.</p></section>';}
  const items = paths
    .map((path) => {
      const entry =
        path.entry === undefined
          ? '(no route)'
          : `${path.entry.method} ${path.entry.path} auth: ${path.entry.auth}`;
      const steps = path.steps
        .map((step) => `${step.file}${step.line !== undefined ? `:${step.line}` : ''} ${step.note}`)
        .join(' → ');
      const tail = steps.length > 0 ? ` → ${esc(steps)}` : '';
      return `<li>${esc(entry)} → ${esc(path.sink.ruleId)}${tail}</li>`;
    })
    .join('\n');
  return `<section id="paths"><h2>Paths</h2><ol>\n${items}\n</ol></section>`;
}

function location(finding: Finding): string {
  if (finding.file === undefined) {return '(project)';}
  return finding.line !== undefined ? `${finding.file}:${finding.line}` : finding.file;
}

function articleHtml(finding: Finding, edges: boolean): string {
  const edge = edges ? taintEdgeLine(finding) : undefined;
  const edgeRow = edge === undefined ? '' : `\n  <p class="taint">${esc(edge)}</p>`;
  const explanation =
    finding.explanation !== undefined && finding.explanation.length > 0
      ? `<p class="explain">${esc(finding.explanation)}</p>`
      : '';
  return `<article class="finding ${esc(finding.severity)}">
  <h3>${esc(finding.ruleId)} — ${esc(finding.title)}</h3>
  <p class="where">${esc(location(finding))}</p>
  <p>${esc(finding.message)}</p>
  <p class="fix">Fix: ${esc(finding.remediation)}</p>
  ${explanation}${edgeRow}
</article>`;
}

/** Standalone HTML report. Finding text is escaped; secrets are already masked. */
export function renderHtmlReport(input: ScanResult, edges = false): string {
  const result = redactScan(input);
  const sections: string[] = [];
  const bySeverityDesc = [...SEVERITIES].reverse();
  for (const severity of bySeverityDesc) {
    const group = result.findings.filter((f) => f.severity === severity);
    if (group.length === 0) {continue;}
    const items = group.map((f) => articleHtml(f, edges)).join('\n');
    sections.push(`<h2>${esc(severity)} (${group.length})</h2>\n${items}`);
  }
  if (sections.length === 0) {
    sections.push('<p>No findings.</p>');
  }
  const findingsBody = sections.join('\n');
  const body =
    result.paths === undefined
      ? findingsBody
      : `<nav class="tabs"><a href="#findings">Findings</a> <a href="#paths">Paths</a></nav>
<section id="findings">
${findingsBody}
</section>
${renderPaths(result.paths)}`;
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
  ${body}
</body>
</html>
`;
}
