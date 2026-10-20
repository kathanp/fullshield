import type { Finding } from './finding.js';

const IGNORE =
  /fullshield-ignore\s+([A-Z0-9-]+)\s*:\s*(\S+)/;

export function parseIgnore(line: string): { ruleId: string; reason: string } | undefined {
  const match = IGNORE.exec(line);
  if (match?.[1] === undefined || match[2] === undefined) {return undefined;}
  return { ruleId: match[1], reason: match[2] };
}

/**
 * Drop findings whose file:line is immediately preceded by
 * `fullshield-ignore RULE-ID: reason` (reason required). Same-line comments
 * also count.
 */
export function applyInlineSuppressions(
  findings: readonly Finding[],
  sources: Readonly<Record<string, string>>,
): Finding[] {
  return findings.filter((finding) => {
    if (finding.file === undefined || finding.line === undefined) {return true;}
    const text = sources[finding.file];
    if (text === undefined) {return true;}
    const lines = text.split(/\r?\n/);
    const current = lines[finding.line - 1] ?? '';
    const previous = finding.line >= 2 ? (lines[finding.line - 2] ?? '') : '';
    for (const line of [current, previous]) {
      const ignore = parseIgnore(line);
      if (ignore !== undefined && ignore.ruleId === finding.ruleId) {return false;}
    }
    return true;
  });
}
