import type { ScanResult } from '../core/engine.js';
import { failsCi, SEVERITIES, type Finding, type Severity } from '../core/finding.js';

export function totalsText(summary: { total: number; bySeverity: Record<Severity, number> }): string {
  const counts = [...SEVERITIES].reverse()
    .filter((severity) => summary.bySeverity[severity] > 0)
    .map((severity) => `${summary.bySeverity[severity]} ${severity}`)
    .join(', ');
  return `${summary.total} findings: ${counts}`;
}

export function decisionText(findings: readonly Finding[], failOn: Severity): string {
  const above = findings.filter((finding) => failsCi(finding, failOn)).length;
  if (above === 0) {return 'pass';}
  return `fail (failOn ${failOn}, ${above} at or above)`;
}

export function terminalFix(finding: Finding): string {
  if (finding.module === 'secrets' || finding.remediation.startsWith('Rotate this credential')) {
    return 'Rotate it, then load it from the environment.';
  }
  const see = finding.remediation.indexOf('. See http');
  if (see === -1) {return finding.remediation;}
  const head = finding.remediation.slice(0, see);
  if (head === finding.title) {return 'Change the flagged call. The docs line names the rule.';}
  return head;
}

export function docsTarget(finding: Finding): string {
  const match = /https:\/\/cwe\.mitre\.org\S*/.exec(finding.remediation);
  const url = match?.[0] ?? '';
  const base = `rules/${finding.ruleId}.md`;
  return url.length > 0 ? `${base} ${url}` : base;
}

function maliciousLine(findings: readonly Finding[]): string | undefined {
  const hit = findings.find((finding) => finding.ruleId === 'DEPS-MALICIOUS-001');
  if (hit === undefined) {return undefined;}
  return `Remove ${hit.snippet ?? hit.title}. It is flagged malicious. Reinstall and rotate credentials.`;
}

function bumpMatches(finding: Finding, name: string): boolean {
  const high = finding.severity === 'critical' || finding.severity === 'high';
  const reach = finding.reachability === 'reachable'
    || finding.reachability === 'reachable-via-dependency'
    || finding.reachability === 'symbol-reachable';
  return finding.ruleId === 'DEPS-VULN-001' && high && reach && (finding.snippet ?? '').startsWith(`${name}@`);
}

function bumpLine(result: ScanResult): string | undefined {
  const bumps = result.metadata.upgradePlan?.bumps ?? [];
  for (const bump of bumps) {
    if (result.findings.some((finding) => bumpMatches(finding, bump.name))) {
      return `Upgrade ${bump.name} ${bump.from} → ${bump.to}.`;
    }
  }
  return undefined;
}

function shownSecret(finding: Finding): boolean {
  if (finding.module !== 'secrets' || finding.file === undefined) {return false;}
  return finding.severity === 'high' || finding.severity === 'critical' || finding.confidence === 'high';
}

function secretLine(findings: readonly Finding[]): string | undefined {
  const hit = findings.find(shownSecret);
  if (hit?.file === undefined) {return undefined;}
  const where = hit.line !== undefined ? `${hit.file}:${hit.line}` : hit.file;
  return `Rotate the secret at ${where}.`;
}

function extraLines(result: ScanResult): string[] {
  const lines: string[] = [];
  const sentence = result.metadata.upgradePlan?.sentence ?? '';
  if (sentence.length > 0) {lines.push(sentence);}
  const unused = result.metadata.unusedDirect;
  if (unused === undefined) {return lines;}
  const packageWord = unused.packages.length === 1 ? 'package is' : 'packages are';
  const advisoryWord = unused.advisories === 1 ? 'advisory' : 'advisories';
  lines.push(`${unused.packages.length} ${packageWord} never imported; removing them clears ${unused.advisories} ${advisoryWord}.`);
  return lines;
}

/** At most three actions, then the upgrade and unused sentences. */
export function firstBlock(result: ScanResult): string[] {
  const items = [maliciousLine(result.findings), bumpLine(result), secretLine(result.findings)]
    .filter((item): item is string => item !== undefined);
  const extra = extraLines(result);
  if (items.length === 0 && extra.length === 0) {return [];}
  return ['Do this first', ...items.map((item, index) => `${index + 1}. ${item}`), ...extra];
}
