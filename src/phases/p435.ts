/**
 * Phase 435. Summary page.
 * Off unless FULLSHIELD_EXPERIMENTAL_SUMMARY=1.
 * Flag off: the command errors with FS-E.
 * The template is fixed. It has no score and none of the marketing ban-list words.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SUMMARY';

export const BANNED_WORDS = [
  'number 1',
  'best',
  'leader',
  'one of a kind',
  'complete protection',
  'prevents attacks',
  'full shield from cyber attacks',
  'risk score',
] as const;

export const SUMMARY_TEMPLATE = [
  'Counts are unreviewed unless the history row says a human reviewed them.',
  'Severity',
  'Module',
  'Top rules by count',
].join('\n');

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface SummaryFinding {
  severity: string;
  module: string;
  ruleId: string;
  reviewed?: boolean;
}

export interface SummaryResult {
  exitCode: number;
  code?: 'FS-E';
  text: string;
  json: Record<string, unknown> | null;
  scanned: false;
}

function counts(findings: readonly SummaryFinding[], key: 'severity' | 'module'): Record<string, number> {
  const out: Record<string, number> = {};
  for (const finding of findings) {
    const name = finding[key];
    out[name] = (out[name] ?? 0) + 1;
  }
  return out;
}

function topRules(findings: readonly SummaryFinding[]): Array<{ ruleId: string; count: number }> {
  const map = new Map<string, number>();
  for (const finding of findings) {
    map.set(finding.ruleId, (map.get(finding.ruleId) ?? 0) + 1);
  }
  return [...map.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .map(([ruleId, count]) => ({ ruleId, count }));
}

export function summarize(findings: readonly SummaryFinding[] | null): SummaryResult {
  if (!enabled()) {
    return { exitCode: 1, code: 'FS-E', text: 'FS-E summary is experimental', json: null, scanned: false };
  }
  const rows = findings ?? [];
  const reviewed = rows.some((row) => row.reviewed === true);
  const sentence = reviewed
    ? 'Counts are unreviewed unless the history row says a human reviewed them.'
    : 'Counts are unreviewed unless the history row says a human reviewed them.';
  const bySeverity = counts(rows, 'severity');
  const byModule = counts(rows, 'module');
  const top = topRules(rows);
  const text = [
    SUMMARY_TEMPLATE,
    sentence,
    `severity ${JSON.stringify(bySeverity)}`,
    `module ${JSON.stringify(byModule)}`,
    `by count ${top.map((row) => `${row.ruleId} ${row.count}`).join(', ')}`,
    `total ${rows.length}`,
  ].join('\n');
  return {
    exitCode: 0,
    text,
    json: { unreviewed: !reviewed, bySeverity, byModule, topByCount: top, total: rows.length },
    scanned: false,
  };
}
