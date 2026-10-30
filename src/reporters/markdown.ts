import type { ScanResult } from '../core/engine.js';
import { SEVERITIES, type Finding, type Severity } from '../core/finding.js';
import { decisionText, docsTarget, firstBlock, totalsText } from './lead.js';
import { redactScan } from './redact.js';

function location(finding: Finding): string {
  if (finding.file === undefined) {return '(project)';}
  return finding.line !== undefined ? `${finding.file}:${finding.line}` : finding.file;
}

function findingLines(finding: Finding): string[] {
  const lines = [`- **Where:** \`${location(finding)}\``];
  if (finding.reachability !== undefined) {lines.push(`- **Reachability:** ${finding.reachability}`);}
  if (finding.dependencyPath !== undefined && finding.dependencyPath.length > 0) {
    lines.push(`- **Path:** ${finding.dependencyPath.join(' > ')}`);
  }
  if (finding.snippet !== undefined) {lines.push(`- **Snippet:** \`${finding.snippet}\``);}
  lines.push(`- **Issue:** ${finding.message}`);
  lines.push(`- **Fix:** ${finding.remediation}`);
  if (finding.trace !== undefined && finding.trace.length > 0) {
    lines.push('- **Trace:**');
    for (const step of finding.trace) {
      const line = step.line !== undefined ? `:${step.line}` : '';
      lines.push(`  - \`${step.file}${line}\` ${step.note}`);
    }
  }
  if (finding.explanation !== undefined) {lines.push(`- **Explain:** ${finding.explanation}`);}
  lines.push(`- **Docs:** ${docsTarget(finding)}`);
  return lines;
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

function severitySection(severity: Severity, findings: readonly Finding[]): string[] {
  const matched = findings.filter((finding) => finding.severity === severity);
  if (matched.length === 0) {return [];}
  const lines = ['', `## ${severity} (${matched.length})`];
  for (const group of groupByRule(matched)) {
    const first = group[0];
    if (first === undefined) {continue;}
    const mark = group.length > 1 ? ` × ${group.length}` : '';
    lines.push('', `### ${first.ruleId} — ${first.title}${mark}`);
    for (const finding of group) {lines.push(...findingLines(finding), '');}
  }
  return lines;
}

function decisionLine(result: ScanResult): string {
  const word = decisionText(result.findings, result.config.failOn);
  if (word === 'pass') {return 'Pass: failOn is ' + result.config.failOn + '.';}
  return `Fail: failOn is ${result.config.failOn}. ${word}.`;
}

/** Markdown report. Same opening as the terminal, with every location under a repeated rule. */
export function renderMarkdownReport(input: ScanResult): string {
  const result = redactScan(input);
  const { findings, summary, metadata } = result;
  const lines = [
    '# FullShield report',
    '',
    `FullShield v${metadata.version} — scanned ${metadata.filesScanned} files in ${metadata.durationMs}ms.`,
  ];
  if (summary.total > 0) {lines.push('', `**${totalsText(summary)}.**`, decisionLine(result));}
  const lead = firstBlock(result);
  if (lead.length > 0) {
    lines.push('', '## Do this first');
    for (const item of lead.slice(1)) {lines.push(item);}
  }
  for (const severity of [...SEVERITIES].reverse()) {lines.push(...severitySection(severity, findings));}
  if (findings.length === 0) {lines.push('', 'No findings.');}
  lines.push('');
  return lines.join('\n');
}
