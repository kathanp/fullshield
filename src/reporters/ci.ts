import type { ScanResult } from '../core/engine.js';
import { lineIndependentFingerprint } from '../core/fingerprint.js';
import { meetsThreshold, type Finding, type Severity } from '../core/finding.js';
import { redactScan } from './redact.js';

const MESSAGE_CAP = 4000;

function posix(file: string): string {
  return file.replace(/\\/g, '/');
}

function clip(text: string): string {
  return text.length <= MESSAGE_CAP ? text : `${text.slice(0, MESSAGE_CAP)}…`;
}

/** GitHub workflow-command escaping. `%` is replaced first so later escapes stay intact. */
function githubEscape(value: string, property: boolean): string {
  let out = value.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A').replace(/:/g, '%3A');
  if (property) {out = out.replace(/,/g, '%2C');}
  return out;
}

function githubLevel(severity: Severity): 'error' | 'warning' | 'notice' {
  if (severity === 'critical' || severity === 'high') {return 'error';}
  if (severity === 'medium') {return 'warning';}
  return 'notice';
}

function gitlabSeverity(severity: Severity): 'info' | 'minor' | 'major' | 'critical' | 'blocker' {
  if (severity === 'info') {return 'info';}
  if (severity === 'low') {return 'minor';}
  if (severity === 'medium') {return 'major';}
  if (severity === 'high') {return 'critical';}
  return 'blocker';
}

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function oneLine(value: string): string {
  return value.replace(/\s+/g, ' ').trim();
}

/**
 * GitHub Actions workflow commands.
 * Critical and high are `error`, medium is `warning`, low and info are `notice`.
 */
export function renderGithubAnnotations(input: ScanResult): string {
  const result = redactScan(input);
  if (result.findings.length === 0) {
    return '::notice title=FullShield::No findings\n';
  }
  const lines = result.findings.map((finding) => {
    const props: string[] = [];
    if (finding.file !== undefined) {props.push(`file=${githubEscape(posix(finding.file), true)}`);}
    if (finding.line !== undefined) {props.push(`line=${finding.line}`);}
    if (finding.column !== undefined) {props.push(`col=${finding.column + 1}`);}
    props.push(`title=${githubEscape(finding.ruleId, true)}`);
    const message = githubEscape(clip(finding.message), false);
    return `::${githubLevel(finding.severity)} ${props.join(',')}::${message}`;
  });
  return `${lines.join('\n')}\n`;
}

function junitCase(finding: Finding): string {
  const file = finding.file !== undefined ? posix(finding.file) : 'fullshield';
  const attrs = [
    `name="${xmlEscape(finding.ruleId)}"`,
    `classname="${xmlEscape(file)}"`,
    `file="${xmlEscape(file)}"`,
  ];
  if (finding.line !== undefined) {attrs.push(`line="${finding.line}"`);}
  const open = `<testcase ${attrs.join(' ')}>`;
  if (!meetsThreshold(finding.severity, 'medium')) {
    return `${open}<skipped message="${xmlEscape(oneLine(clip(finding.message)))}"/></testcase>`;
  }
  const detail = clip(`${finding.message}${finding.remediation.length > 0 ? `\nFix: ${finding.remediation}` : ''}`);
  return `${open}<failure type="${finding.severity}" message="${xmlEscape(oneLine(clip(finding.message)))}">${xmlEscape(detail)}</failure></testcase>`;
}

/**
 * JUnit XML. Medium and above are failures. Low and info are skipped.
 * An empty scan is one passing testcase.
 */
export function renderJunitReport(input: ScanResult): string {
  const result = redactScan(input);
  const header = '<?xml version="1.0" encoding="UTF-8"?>';
  if (result.findings.length === 0) {
    return `${header}\n<testsuites name="fullshield" tests="1" failures="0" skipped="0"><testsuite name="fullshield" tests="1" failures="0" skipped="0"><testcase name="scan" classname="fullshield"/></testsuite></testsuites>\n`;
  }
  const groups = new Map<string, Finding[]>();
  for (const finding of result.findings) {
    const list = groups.get(finding.module) ?? [];
    list.push(finding);
    groups.set(finding.module, list);
  }
  let failures = 0;
  let skipped = 0;
  const suites: string[] = [];
  for (const [name, findings] of groups) {
    let suiteFailures = 0;
    let suiteSkipped = 0;
    const cases = findings.map((finding) => {
      if (meetsThreshold(finding.severity, 'medium')) {suiteFailures += 1;}
      else {suiteSkipped += 1;}
      return junitCase(finding);
    });
    failures += suiteFailures;
    skipped += suiteSkipped;
    suites.push(
      `<testsuite name="${xmlEscape(name)}" tests="${findings.length}" failures="${suiteFailures}" skipped="${suiteSkipped}">${cases.join('')}</testsuite>`,
    );
  }
  return `${header}\n<testsuites name="fullshield" tests="${result.findings.length}" failures="${failures}" skipped="${skipped}">${suites.join('')}</testsuites>\n`;
}

/** GitLab Code Quality report. Severities map to info, minor, major, critical, blocker. */
export function renderGitlabCodeQuality(input: ScanResult): string {
  const result = redactScan(input);
  const report = result.findings.map((finding) => {
    const path = finding.file !== undefined ? posix(finding.file) : '.';
    const location: { path: string; lines?: { begin: number } } = { path };
    if (finding.line !== undefined) {location.lines = { begin: finding.line };}
    return {
      description: clip(finding.message),
      check_name: finding.ruleId,
      fingerprint: lineIndependentFingerprint(finding),
      severity: gitlabSeverity(finding.severity),
      location,
    };
  });
  return `${JSON.stringify(report, null, 2)}\n`;
}
