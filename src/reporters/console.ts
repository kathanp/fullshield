import pc from 'picocolors';

import type { ScanResult } from '../core/engine.js';
import { SEVERITIES, type Finding, type Severity } from '../core/finding.js';
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
    `    ${pc.green('fix:')} ${finding.remediation}`,
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
  if (snippet === undefined || snippet.length === 0) return undefined;
  if (snippet.startsWith('@')) {
    const second = snippet.indexOf('@', 1);
    return second === -1 ? snippet : snippet.slice(0, second);
  }
  const at = snippet.indexOf('@');
  return at <= 0 ? snippet : snippet.slice(0, at);
}

function versionsFromSnippet(snippet: string | undefined): string[] {
  const name = packageNameFromSnippet(snippet);
  if (name === undefined || snippet === undefined) return [];
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
  if (finding.ruleId === 'DEPS-MALICIOUS-001') return true;
  if (finding.ruleId === 'DEPS-VULN-001') {
    if (isDevOnly(finding)) return false;
    return finding.reachability !== undefined && SHOWN_VULN_REACH.has(finding.reachability);
  }
  if (finding.module === 'sast' || finding.module === 'secrets' || finding.module === 'config') {
    return finding.severity === 'high' || finding.severity === 'critical' || finding.confidence === 'high';
  }
  return false;
}

function reachRank(finding: Finding): number {
  const reachability = finding.reachability;
  if (reachability === 'reachable' || reachability === 'symbol-reachable') return 0;
  if (reachability === 'reachable-via-dependency') return 1;
  if (reachability === 'reachability-unknown') return 2;
  if (reachability === undefined) return 4;
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
      if (list === undefined) groups.set(name, [finding]);
      else list.push(finding);
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
    if (first === undefined) continue;
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
  rows.sort((a, b) => {
    const probeA = a.findings[0];
    const probeB = b.findings[0];
    if (probeA === undefined || probeB === undefined) return 0;
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
  });
  return rows;
}

function renderRow(row: ConsoleRow): string[] {
  if (!row.grouped) {
    const only = row.findings[0];
    if (only === undefined) return [];
    return [...renderFinding(only), `    docs: rules/${only.ruleId}.md`];
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
  lines.push(`    docs: rules/${row.ruleId}.md`);
  return lines;
}

export interface ConsoleReportOptions {
  /** Print every finding, with no 20-row cap. */
  all?: boolean;
}

/** Human-readable report. Default view is the actionable rows. JSON is unchanged. */
export function renderConsoleReport(input: ScanResult, options: ConsoleReportOptions = {}): string {
  const result = redactScan(input);
  const { findings, summary, metadata } = result;
  const lines: string[] = [];

  lines.push(
    pc.bold(`FullShield v${metadata.version}`) +
      pc.dim(
        ` — scanned ${metadata.filesScanned} files in ${metadata.durationMs}ms` +
          ` (modules: ${metadata.modulesRun.length > 0 ? metadata.modulesRun.join(', ') : 'none'})`,
      ),
  );
  if (metadata.history !== undefined) lines.push(metadata.history);
  if (metadata.unusedDirect !== undefined) {
    const count = metadata.unusedDirect.packages.length;
    const advisories = metadata.unusedDirect.advisories;
    const packageWord = count === 1 ? 'package is' : 'packages are';
    const advisoryWord = advisories === 1 ? 'advisory' : 'advisories';
    lines.push(
      `${count} ${packageWord} never imported; removing them clears ${advisories} ${advisoryWord}.`,
    );
  }

  if (metadata.modulesRun.length < metadata.modulesRequested.length) {
    const pending = metadata.modulesRequested.filter((m) => !metadata.modulesRun.includes(m));
    lines.push(
      pc.dim(`note: requested modules not implemented yet: ${pending.join(', ')}`),
    );
  }

  const showAll = options.all === true;
  const folded = findings.filter((finding) => !isActionable(finding));
  const rows = showAll
    ? [...findings].sort(compareActionable).map((finding) => ({
        findings: [finding],
        severity: finding.severity,
        reachability: finding.reachability,
        ruleId: finding.ruleId,
        file: finding.file,
        line: finding.line,
        versions: [] as string[],
        grouped: false,
      }))
    : shownConsoleRows(findings);
  const printed = showAll ? rows : rows.slice(0, 20);
  const hiddenActionable = showAll ? 0 : rows.length - printed.length;
  let previous: Severity | undefined;
  for (const row of printed) {
    if (row.severity !== previous) {
      const count = printed.filter((item) => item.severity === row.severity).length;
      lines.push('');
      lines.push(SEVERITY_COLOR[row.severity](`${row.severity.toUpperCase()} (${count})`));
      previous = row.severity;
    }
    lines.push(...renderRow(row));
  }
  if (hiddenActionable > 0) {
    lines.push('');
    lines.push(`${hiddenActionable} more actionable — use --json`);
  }
  if (!showAll && folded.length > 0) {
    lines.push('');
    lines.push(
      `${folded.length} more (not directly reachable, or below high confidence) — --all or see JSON`,
    );
  }

  lines.push('');
  if (summary.total === 0) {
    lines.push(pc.green('✔ No findings.'));
  } else {
    const bySeverityDesc = [...SEVERITIES].reverse();
    const counts = bySeverityDesc
      .filter((s) => summary.bySeverity[s] > 0)
      .map((s) => `${summary.bySeverity[s]} ${s}`)
      .join(', ');
    lines.push(pc.red(`✖ ${summary.total} finding(s): ${counts}`));
  }

  return lines.join('\n');
}
