import pc from 'picocolors';

import type { ScanResult } from '../core/engine.js';
import { SEVERITIES, type Finding, type Severity } from '../core/finding.js';

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

/** Human-readable report: findings grouped by severity, highest first. */
export function renderConsoleReport(result: ScanResult): string {
  const { findings, summary, metadata } = result;
  const lines: string[] = [];

  lines.push(
    pc.bold(`FullShield v${metadata.version}`) +
      pc.dim(
        ` — scanned ${metadata.filesScanned} files in ${metadata.durationMs}ms` +
          ` (modules: ${metadata.modulesRun.length > 0 ? metadata.modulesRun.join(', ') : 'none'})`,
      ),
  );

  if (metadata.modulesRun.length < metadata.modulesRequested.length) {
    const pending = metadata.modulesRequested.filter((m) => !metadata.modulesRun.includes(m));
    lines.push(
      pc.dim(`note: requested modules not implemented yet: ${pending.join(', ')}`),
    );
  }

  const bySeverityDesc = [...SEVERITIES].reverse();
  for (const severity of bySeverityDesc) {
    const group = findings.filter((f) => f.severity === severity);
    if (group.length === 0) continue;
    lines.push('');
    lines.push(SEVERITY_COLOR[severity](`${severity.toUpperCase()} (${group.length})`));
    for (const finding of group) {
      lines.push(...renderFinding(finding));
    }
  }

  lines.push('');
  if (summary.total === 0) {
    lines.push(pc.green('✔ No findings.'));
  } else {
    const counts = bySeverityDesc
      .filter((s) => summary.bySeverity[s] > 0)
      .map((s) => `${summary.bySeverity[s]} ${s}`)
      .join(', ');
    lines.push(pc.red(`✖ ${summary.total} finding(s): ${counts}`));
  }

  return lines.join('\n');
}
