import { SEVERITIES, sortFindings, type Finding } from '../core/finding.js';

const RULE_DOCS_BASE = 'https://github.com/kathanp/fullshield/blob/main/rules';

/** Stable GitHub URL for a shipped rule doc (also valid as a GitLab-comment link). */
export function ruleDocsUrl(ruleId: string): string {
  return `${RULE_DOCS_BASE}/${ruleId}.md`;
}

function location(finding: Finding): string {
  if (finding.file === undefined) {return '(project)';}
  return finding.line !== undefined ? `${finding.file}:${finding.line}` : finding.file;
}

/**
 * Deterministic Markdown for a GitHub/GitLab PR comment: new findings versus
 * baseline (callers pass `applyBaseline` / `diffNewFindings` results). No AI.
 */
export function renderPrSummary(
  findings: readonly Finding[],
  opts: { baseLabel?: string } = {},
): string {
  const baseLabel = opts.baseLabel ?? 'baseline';
  const next = sortFindings(findings.filter((f) => f.source !== 'ai'));
  const lines = [
    '# FullShield PR summary',
    '',
    `${next.length} new finding(s) versus ${baseLabel}.`,
  ];
  if (next.length === 0) {
    return `${lines.join('\n')}\n`;
  }
  lines.push('');
  for (const severity of [...SEVERITIES].reverse()) {
    const group = next.filter((f) => f.severity === severity);
    if (group.length === 0) {continue;}
    lines.push(`## ${severity} (${group.length})`, '');
    for (const finding of group) {
      lines.push(
        `- [\`${finding.ruleId}\`](${ruleDocsUrl(finding.ruleId)}) \`${location(finding)}\` — ${finding.message}`,
      );
    }
    lines.push('');
  }
  while (lines[lines.length - 1] === '') {lines.pop();}
  return `${lines.join('\n')}\n`;
}
