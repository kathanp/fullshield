import type { ScanResult } from '../core/engine.js';
import { SEVERITIES, type Finding, type Severity } from '../core/finding.js';
import { taintEdgeLine } from '../modules/sast/parity.js';
import type { AttackPath } from '../paths/types.js';
import { decisionText, docsTarget, firstBlock, totalsText } from './lead.js';
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

function decisionLine(result: ScanResult): string {
  const word = decisionText(result.findings, result.config.failOn);
  if (word === 'pass') {return `Pass: failOn is ${result.config.failOn}.`;}
  return `Fail: failOn is ${result.config.failOn}. ${word}.`;
}

function traceHtml(finding: Finding): string {
  if (finding.trace === undefined || finding.trace.length === 0) {return '';}
  const items = finding.trace.map((step) => {
    const line = step.line !== undefined ? `:${step.line}` : '';
    return `<li>${esc(`${step.file}${line}`)} ${esc(step.note)}</li>`;
  });
  return `<ul class="trace">\n${items.join('\n')}\n</ul>`;
}

function findingHtml(finding: Finding, edges: boolean): string {
  const rows = [
    `<article class="finding ${esc(finding.severity)}">`,
    `  <p class="title">${esc(finding.title)}</p>`,
    `  <p class="where">${esc(location(finding))}</p>`,
  ];
  if (finding.reachability !== undefined) {rows.push(`  <p>Reachability: ${esc(finding.reachability)}</p>`);}
  if (finding.dependencyPath !== undefined && finding.dependencyPath.length > 0) {
    rows.push(`  <p>Path: ${esc(finding.dependencyPath.join(' > '))}</p>`);
  }
  if (finding.snippet !== undefined) {rows.push(`  <p class="snippet">${esc(finding.snippet)}</p>`);}
  rows.push(`  <p>${esc(finding.message)}</p>`);
  rows.push(`  <p class="fix">Fix: ${esc(finding.remediation)}</p>`);
  const trace = traceHtml(finding);
  if (trace.length > 0) {rows.push(trace);}
  if (finding.explanation !== undefined && finding.explanation.length > 0) {
    rows.push(`  <p class="explain">${esc(finding.explanation)}</p>`);
  }
  rows.push(`  <p class="docs">Docs: ${esc(docsTarget(finding))}</p>`);
  const edge = edges ? taintEdgeLine(finding) : undefined;
  if (edge !== undefined) {rows.push(`  <p class="taint">${esc(edge)}</p>`);}
  rows.push('</article>');
  return rows.join('\n');
}

function groupByRule(findings: readonly Finding[]): Finding[][] {
  const groups: Finding[][] = [];
  const index = new Map<string, number>();
  for (const finding of findings) {
    const at = index.get(finding.ruleId);
    if (at === undefined) {
      index.set(finding.ruleId, groups.length);
      groups.push([finding]);
      continue;
    }
    groups[at]?.push(finding);
  }
  return groups;
}

function severityHtml(severity: Severity, findings: readonly Finding[], edges: boolean): string {
  const matched = findings.filter((finding) => finding.severity === severity);
  if (matched.length === 0) {return '';}
  const parts = [`<h2>${esc(severity)} (${matched.length})</h2>`];
  for (const group of groupByRule(matched)) {
    const first = group[0];
    if (first === undefined) {continue;}
    const mark = group.length > 1 ? ` × ${group.length}` : '';
    parts.push(`<h3>${esc(first.ruleId)} — ${esc(first.title)}${mark}</h3>`);
    for (const finding of group) {parts.push(findingHtml(finding, edges));}
  }
  return parts.join('\n');
}

function openingHtml(result: ScanResult): string {
  const { metadata, summary } = result;
  const lines = [
    `<p>FullShield v${esc(metadata.version)} — scanned ${metadata.filesScanned} files in ${metadata.durationMs}ms.</p>`,
    `<p>${esc(decisionLine(result))}</p>`,
  ];
  if (summary.total > 0) {lines.push(`<p><strong>${esc(totalsText(summary))}.</strong></p>`);}
  const lead = firstBlock(result);
  if (lead.length === 0) {return lines.join('\n');}
  lines.push('<h2>Do this first</h2>', '<ol>');
  for (const item of lead.slice(1)) {
    if (/^\d+\. /.test(item)) {lines.push(`<li>${esc(item.replace(/^\d+\. /, ''))}</li>`);}
  }
  lines.push('</ol>');
  for (const item of lead.slice(1)) {
    if (!/^\d+\. /.test(item)) {lines.push(`<p>${esc(item)}</p>`);}
  }
  return lines.join('\n');
}

function findingsHtml(result: ScanResult, edges: boolean): string {
  const sections = [...SEVERITIES].reverse()
    .map((severity) => severityHtml(severity, result.findings, edges))
    .filter((section) => section.length > 0);
  if (sections.length === 0) {sections.push('<p>No findings.</p>');}
  return sections.join('\n');
}

function documentHtml(result: ScanResult, edges: boolean): string {
  const findingsBody = findingsHtml(result, edges);
  const body = result.paths === undefined
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
  ${openingHtml(result)}
  ${body}
</body>
</html>
`;
}

/** Standalone HTML report. Finding text is escaped; secrets are already masked. */
export function renderHtmlReport(input: ScanResult, edges = false): string {
  return documentHtml(redactScan(input), edges);
}
