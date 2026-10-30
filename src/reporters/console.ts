import pc from 'picocolors';

import type { ScanResult } from '../core/engine.js';
import { SEVERITIES, type Finding, type Severity } from '../core/finding.js';
import { compareByPriority, priorityEnabled } from '../priority/score.js';
import type { AttackPath } from '../paths/types.js';
import { decisionText, docsTarget, firstBlock, terminalFix, totalsText } from './lead.js';
import { redactScan } from './redact.js';

const SEVERITY_COLOR: Record<Severity, (text: string) => string> = {
  critical: (t) => pc.bold(pc.red(t)),
  high: (t) => pc.red(t),
  medium: (t) => pc.yellow(t),
  low: (t) => pc.cyan(t),
  info: (t) => pc.dim(t),
};

function renderFinding(finding: Finding): string[] {
  const location =
    finding.file !== undefined
      ? `${finding.file}${finding.line !== undefined ? `:${finding.line}` : ''}`
      : '(project)';
  const lines = [
    `  ${pc.bold(`[${finding.ruleId}]`)} ${finding.title} ${pc.dim(`(${location})`)}`,
    `    ${finding.message}`,
    `    ${pc.green('fix:')} ${terminalFix(finding)}`,
  ];
  if (finding.snippet !== undefined) {
    lines.splice(1, 0, `    ${pc.dim(finding.snippet)}`);
  }
  if (finding.reachability !== undefined) {
    const path =
      finding.dependencyPath !== undefined && finding.dependencyPath.length > 0
        ? ` (${finding.dependencyPath.join(' > ')})`
        : '';
    lines.push(`    ${pc.dim(`reachability: ${finding.reachability}${path}`)}`);
  }
  if (finding.trace !== undefined && finding.trace.length > 0) {
    lines.push(
      `    ${pc.dim(`trace: ${finding.trace.map((s) => `${s.file}${s.line !== undefined ? `:${s.line}` : ''}`).join(' → ')}`)}`,
    );
  }
  if (finding.explanation !== undefined && finding.explanation.length > 0) {
    lines.push(`    ${pc.dim(`explain: ${finding.explanation}`)}`);
  }
  if (finding.introducedIn !== undefined) {
    lines.push(
      `    ${pc.dim(`introduced in ${finding.introducedIn}${finding.stillAtHead === false ? ' (not at HEAD)' : finding.stillAtHead === true ? ' (still at HEAD)' : ''}`)}`,
    );
  }
  if (finding.verification !== undefined) {
    lines.push(`    ${pc.dim(`verification: ${finding.verification}`)}`);
  }
  return lines;
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SHOWN_VULN_REACH = new Set<NonNullable<Finding['reachability']>>([
  'reachable',
  'symbol-reachable',
  'reachable-via-dependency',
  'reachability-unknown',
]);

function packageNameFromSnippet(snippet: string | undefined): string | undefined {
  if (snippet === undefined || snippet.length === 0) {return undefined;}
  if (snippet.startsWith('@')) {
    const second = snippet.indexOf('@', 1);
    return second === -1 ? snippet : snippet.slice(0, second);
  }
  const at = snippet.indexOf('@');
  return at <= 0 ? snippet : snippet.slice(0, at);
}

function versionsFromSnippet(snippet: string | undefined): string[] {
  const name = packageNameFromSnippet(snippet);
  if (name === undefined || snippet === undefined) {return [];}
  const rest = snippet.slice(name.length + 1);
  return rest.length === 0 ? [] : rest.split(',').filter((version) => version.length > 0);
}

function isDevOnly(finding: Finding): boolean {
  return finding.message.includes('(dev-only)');
}

/**
 * Console-only. Human decision 2026-10-18.
 * Dependency rows ignore severity and confidence. JSON and other reporters are unchanged.
 */
export function isActionable(finding: Finding): boolean {
  if (finding.ruleId === 'DEPS-MALICIOUS-001') {return true;}
  if (finding.ruleId === 'DEPS-VENDORED-001') {return true;}
  if (finding.ruleId === 'DEPS-UNFIXED-001') {return finding.reachability === 'reachable';}
  if (finding.ruleId === 'DEPS-VULN-001') {
    if (isDevOnly(finding)) {return false;}
    return finding.reachability !== undefined && SHOWN_VULN_REACH.has(finding.reachability);
  }
  if (finding.module === 'sast' || finding.module === 'secrets' || finding.module === 'config') {
    return finding.severity === 'high' || finding.severity === 'critical' || finding.confidence === 'high';
  }
  return false;
}

function formatPath(path: AttackPath): string {
  const entry = path.entry === undefined ? '(no route)' : `${path.entry.method} ${path.entry.path} auth=${path.entry.auth}`;
  const where =
    path.sink.file !== undefined
      ? `${path.sink.file}${path.sink.line !== undefined ? `:${path.sink.line}` : ''}`
      : '(project)';
  return `  ${entry} → [${path.sink.ruleId}] ${where}`;
}

function reachRank(finding: Finding): number {
  const reachability = finding.reachability;
  if (reachability === 'reachable' || reachability === 'symbol-reachable') {return 0;}
  if (reachability === 'reachable-via-dependency') {return 1;}
  if (reachability === 'reachability-unknown') {return 2;}
  if (reachability === undefined) {return 4;}
  return 3;
}

/** Console order only. Malicious first, then severity, reachability, file, line, ruleId. */
export function compareActionable(a: Finding, b: Finding): number {
  const maliciousA = a.ruleId === 'DEPS-MALICIOUS-001' ? 0 : 1;
  const maliciousB = b.ruleId === 'DEPS-MALICIOUS-001' ? 0 : 1;
  return (
    maliciousA - maliciousB ||
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    reachRank(a) - reachRank(b) ||
    (a.file ?? '').localeCompare(b.file ?? '') ||
    (a.line ?? 0) - (b.line ?? 0) ||
    a.ruleId.localeCompare(b.ruleId)
  );
}

interface ConsoleRow {
  findings: Finding[];
  severity: Severity;
  reachability?: Finding['reachability'];
  ruleId: string;
  file?: string;
  line?: number;
  packageName?: string;
  versions: string[];
  path?: string[];
  grouped: boolean;
}

function highestSeverity(findings: readonly Finding[]): Severity {
  return findings.reduce((best, finding) =>
    SEVERITY_RANK[finding.severity] < SEVERITY_RANK[best] ? finding.severity : best,
  findings[0]?.severity ?? 'info');
}

function bestReachability(findings: readonly Finding[]): Finding['reachability'] {
  let best: Finding['reachability'];
  let bestRank = 5;
  for (const finding of findings) {
    const rank = reachRank(finding);
    if (finding.reachability !== undefined && rank < bestRank) {
      best = finding.reachability;
      bestRank = rank;
    }
  }
  return best;
}

/** Grouped console rows for findings that pass the shown rule. */
export function shownConsoleRows(findings: readonly Finding[]): ConsoleRow[] {
  return dependencyRows(findings.filter(isActionable));
}

function dependencyRows(findings: readonly Finding[]): ConsoleRow[] {
  const groups = new Map<string, Finding[]>();
  const singles: Finding[] = [];
  for (const finding of findings) {
    const name = packageNameFromSnippet(finding.snippet);
    if ((finding.ruleId === 'DEPS-VULN-001' || finding.ruleId === 'DEPS-MALICIOUS-001') && name !== undefined) {
      const list = groups.get(name);
      if (list === undefined) {groups.set(name, [finding]);}
      else {list.push(finding);}
    } else {
      singles.push(finding);
    }
  }
  const rows: ConsoleRow[] = singles.map((finding) => ({
    findings: [finding],
    severity: finding.severity,
    reachability: finding.reachability,
    ruleId: finding.ruleId,
    file: finding.file,
    line: finding.line,
    versions: [],
    grouped: false,
  }));
  for (const [packageName, list] of groups) {
    const ordered = [...list].sort(compareActionable);
    const first = ordered[0];
    if (first === undefined) {continue;}
    const versions = [...new Set(list.flatMap((finding) => versionsFromSnippet(finding.snippet)))].sort();
    const malicious = list.find((finding) => finding.ruleId === 'DEPS-MALICIOUS-001');
    rows.push({
      findings: ordered,
      severity: highestSeverity(list),
      reachability: bestReachability(list),
      ruleId: malicious?.ruleId ?? 'DEPS-VULN-001',
      file: first.file,
      line: first.line,
      packageName,
      versions,
      path: first.dependencyPath,
      grouped: true,
    });
  }
  rows.sort(compareRows);
  return rows;
}

function comparePriorityRows(a: ConsoleRow, b: ConsoleRow): number {
  return (
    rowPriority(b) - rowPriority(a) ||
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    (a.file ?? '').localeCompare(b.file ?? '') ||
    (a.line ?? 0) - (b.line ?? 0) ||
    a.ruleId.localeCompare(b.ruleId)
  );
}

function compareDefaultRows(a: ConsoleRow, b: ConsoleRow, probeA: Finding, probeB: Finding): number {
  const maliciousA = a.ruleId === 'DEPS-MALICIOUS-001' ? 0 : 1;
  const maliciousB = b.ruleId === 'DEPS-MALICIOUS-001' ? 0 : 1;
  return (
    maliciousA - maliciousB ||
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    reachRank({ ...probeA, reachability: a.reachability }) - reachRank({ ...probeB, reachability: b.reachability }) ||
    (a.file ?? '').localeCompare(b.file ?? '') ||
    (a.line ?? 0) - (b.line ?? 0) ||
    a.ruleId.localeCompare(b.ruleId)
  );
}

function compareRows(a: ConsoleRow, b: ConsoleRow): number {
  const probeA = a.findings[0];
  const probeB = b.findings[0];
  if (probeA === undefined || probeB === undefined) {return 0;}
  if (priorityEnabled()) {return comparePriorityRows(a, b);}
  return compareDefaultRows(a, b, probeA, probeB);
}

function rowPriority(row: ConsoleRow): number {
  let best = 0;
  for (const finding of row.findings) {
    const score = finding.priority ?? 0;
    if (score > best) {best = score;}
  }
  return best;
}

function groupSameRule(rows: ConsoleRow[]): ConsoleRow[] {
  const out: ConsoleRow[] = [];
  const index = new Map<string, number>();
  for (const row of rows) {
    if (row.packageName !== undefined || row.findings.length !== 1) {
      out.push(row);
      continue;
    }
    const key = `${row.severity}:${row.ruleId}`;
    const at = index.get(key);
    if (at === undefined) {
      index.set(key, out.length);
      out.push({ ...row, findings: [...row.findings] });
      continue;
    }
    const existing = out[at];
    if (existing !== undefined) {existing.findings.push(...row.findings);}
  }
  return out;
}

function findingWhere(finding: Finding): string {
  if (finding.file === undefined) {return '(project)';}
  return finding.line !== undefined ? `${finding.file}:${finding.line}` : finding.file;
}

function detailLines(finding: Finding): string[] {
  const lines = [`    ${findingWhere(finding)}`];
  if (finding.snippet !== undefined) {lines.push(`    ${pc.dim(finding.snippet)}`);}
  if (finding.reachability !== undefined) {lines.push(`    reachability: ${finding.reachability}`);}
  if (finding.dependencyPath !== undefined && finding.dependencyPath.length > 0) {
    lines.push(`    path: ${finding.dependencyPath.join(' > ')}`);
  }
  if (finding.trace !== undefined && finding.trace.length > 0) {
    lines.push(`    trace: ${finding.trace.map((step) => `${step.file}:${step.line ?? ''}`).join(' -> ')}`);
  }
  if (finding.explanation !== undefined) {lines.push(`    explain: ${finding.explanation}`);}
  return lines;
}

function renderRuleGroup(row: ConsoleRow): string[] {
  const first = row.findings[0];
  if (first === undefined) {return [];}
  const lines = [`  ${pc.bold(`[${row.ruleId}]`)} × ${row.findings.length}`];
  for (const finding of row.findings) {lines.push(...detailLines(finding));}
  lines.push(`    ${pc.green('fix:')} ${terminalFix(first)}`);
  lines.push(`    docs: ${docsTarget(first)}`);
  return lines;
}

function shownOf(rows: readonly ConsoleRow[], severity: Severity): number {
  let count = 0;
  for (const row of rows) {
    if (row.severity !== severity) {continue;}
    count += row.findings.filter((finding) => finding.severity === severity).length;
  }
  return count;
}

function renderRow(row: ConsoleRow): string[] {
  if (row.packageName === undefined && row.findings.length > 1) {return renderRuleGroup(row);}
  if (!row.grouped) {
    const only = row.findings[0];
    if (only === undefined) {return [];}
    return [...renderFinding(only), `    docs: ${docsTarget(only)}`];
  }
  const reach = row.reachability ?? 'unspecified';
  const lines = [
    `  ${pc.bold(`[${row.ruleId}]`)} ${row.packageName} — ${row.findings.length} advisories, ${row.severity}, ${reach}`,
    `    versions: ${row.versions.join(', ') || 'unknown'}`,
  ];
  if (row.path !== undefined && row.path.length > 0) {
    lines.push(`    path: ${row.path.join(' > ')}`);
  }
  if (row.file !== undefined) {
    lines.push(`    ${row.file}${row.line !== undefined ? `:${row.line}` : ''}`);
  }
  const first = row.findings[0];
  const evidenceImport = first?.reachabilityEvidence?.imports[0];
  if (evidenceImport !== undefined) {
    lines.push(`    import: ${evidenceImport.file}:${evidenceImport.line} ${evidenceImport.specifier}`);
  }
  if (first !== undefined) {lines.push(`    docs: ${docsTarget(first)}`);}
  return lines;
}

export interface ConsoleReportOptions {
  /** Print every finding, with no 20-row cap. */
  all?: boolean;
}

function reportPreamble(result: ScanResult): string[] {
  const { findings, summary, metadata } = result;
  const lines = [
    pc.bold(`FullShield v${metadata.version}`) +
      pc.dim(
        ` — scanned ${metadata.filesScanned} files in ${metadata.durationMs}ms — ${decisionText(findings, result.config.failOn)}`,
      ),
  ];
  if (summary.total > 0) {lines.push(totalsText(summary));}
  if (metadata.history !== undefined) {lines.push(metadata.history);}
  if (metadata.skipped !== undefined && metadata.skipped.total > 0) {
    lines.push(
      `Skipped ${metadata.skipped.total} files that are not source (oversize ${metadata.skipped.oversize}, minified ${metadata.skipped.minified}, declarations ${metadata.skipped.declaration}, maps ${metadata.skipped.sourceMap}, generated ${metadata.skipped.generated}).`,
    );
  }
  const lead = firstBlock(result);
  if (lead.length > 0) {
    lines.push('');
    lines.push(...lead);
  }
  if (metadata.modulesRun.length < metadata.modulesRequested.length) {
    const pending = metadata.modulesRequested.filter((name) => !metadata.modulesRun.includes(name));
    lines.push(pc.dim(`note: requested modules not implemented yet: ${pending.join(', ')}`));
  }
  return lines;
}

function allRows(findings: readonly Finding[]): ConsoleRow[] {
  const order = priorityEnabled() ? compareByPriority : compareActionable;
  return [...findings].sort(order).map((finding) => ({
    findings: [finding],
    severity: finding.severity,
    reachability: finding.reachability,
    ruleId: finding.ruleId,
    file: finding.file,
    line: finding.line,
    versions: [] as string[],
    grouped: false,
  }));
}

function appendSeverity(lines: string[], printed: readonly ConsoleRow[], severity: Severity, summary: ScanResult['summary']): void {
  const real = summary.bySeverity[severity];
  const shown = shownOf(printed, severity);
  lines.push('');
  lines.push(SEVERITY_COLOR[severity](`${severity.toUpperCase()} (${real})`));
  if (shown < real) {lines.push(`showing ${shown}`);}
}

function appendRows(lines: string[], printed: readonly ConsoleRow[], summary: ScanResult['summary']): void {
  let previous: Severity | undefined;
  for (const row of printed) {
    if (row.severity !== previous) {
      appendSeverity(lines, printed, row.severity, summary);
      previous = row.severity;
    }
    lines.push(...renderRow(row));
  }
}

function appendOverflow(lines: string[], hidden: number, showAll: boolean, folded: readonly Finding[]): void {
  if (hidden > 0) {
    lines.push('');
    lines.push(`${hidden} more: --all and --markdown report.md`);
  }
  if (!showAll && folded.length > 0) {
    lines.push('');
    lines.push(
      `${folded.length} more (not directly reachable, or below high confidence) — --all or --markdown report.md`,
    );
  }
}

function appendClosing(lines: string[], result: ScanResult): void {
  const { summary, metadata } = result;
  lines.push('');
  if (result.paths !== undefined && result.paths.length > 0) {
    lines.push(pc.bold('Attack paths'));
    for (const path of result.paths.slice(0, 5)) {lines.push(formatPath(path));}
    if (result.paths.length > 5) {lines.push(`${result.paths.length - 5} more paths — use --json`);}
    lines.push('');
  }
  if (metadata.incomplete === true) {
    lines.push(pc.yellow(`Scan stopped at budget. ${metadata.filesNotTaintChecked ?? 0} files not taint-checked.`));
  }
  if (summary.total === 0 && metadata.incomplete !== true) {
    lines.push(pc.green('✔ No findings.'));
    return;
  }
  if (summary.total === 0) {return;}
  const counts = [...SEVERITIES].reverse()
    .filter((severity) => summary.bySeverity[severity] > 0)
    .map((severity) => `${summary.bySeverity[severity]} ${severity}`)
    .join(', ');
  lines.push(pc.red(`✖ ${summary.total} finding(s): ${counts}`));
}

/** Human-readable report. Default view is the actionable rows. JSON is unchanged. */
export function renderConsoleReport(input: ScanResult, options: ConsoleReportOptions = {}): string {
  const result = redactScan(input);
  const { findings, summary } = result;
  const lines = reportPreamble(result);
  const showAll = options.all === true;
  const folded = findings.filter((finding) => !isActionable(finding));
  const rows = showAll ? allRows(findings) : groupSameRule(shownConsoleRows(findings));
  const printed = showAll ? rows : rows.slice(0, 20);
  appendRows(lines, printed, summary);
  appendOverflow(lines, showAll ? 0 : rows.length - printed.length, showAll, folded);
  appendClosing(lines, result);
  return lines.join('\n');
}
