/**
 * Phase 429. Suppression audit.
 * Off unless FULLSHIELD_EXPERIMENTAL_SUPPRESS=1.
 * Flag off: findings and comments are returned unchanged and none of the suppression ids are emitted.
 * The user's comment is never deleted.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SUPPRESS';

export const SUPPRESS_ORPHAN = 'SUPPRESS-ORPHAN';
export const SUPPRESS_EXPIRED = 'SUPPRESS-EXPIRED';
export const SUPPRESS_BARE = 'SUPPRESS-BARE';

const DATE = /^\d{4}-\d{2}-\d{2}$/;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface LiveFinding {
  ruleId: string;
  file: string;
  line: number;
  severity: string;
  message: string;
}

export interface SuppressionReport {
  ruleId: typeof SUPPRESS_ORPHAN | typeof SUPPRESS_EXPIRED | typeof SUPPRESS_BARE;
  severity: 'info' | 'medium';
  file: string;
  line: number;
  message: string;
}

interface ParsedSuppression {
  ruleId: string;
  reason: string | null;
  owner: string | null;
  until: string | null;
  bare: boolean;
}

function field(text: string, name: string): string | null {
  const quoted = new RegExp(`${name}="([^"]*)"`).exec(text);
  if (quoted?.[1] !== undefined) {
    return quoted[1];
  }
  const plain = new RegExp(`${name}=(\\S+)`).exec(text);
  return plain?.[1] ?? null;
}

export function parseSuppression(comment: string): ParsedSuppression | null {
  const match = /fullshield-suppress\s+(\S+)/.exec(comment);
  const ruleId = match?.[1];
  if (ruleId === undefined) {
    return null;
  }
  const reason = field(comment, 'reason');
  const owner = field(comment, 'owner');
  const until = field(comment, 'until');
  const badDate = until !== null && !DATE.test(until);
  const bare = reason === null || reason.length === 0 || owner === null || owner.length === 0 || badDate;
  return { ruleId, reason, owner, until, bare };
}

function report(ruleId: SuppressionReport['ruleId'], severity: SuppressionReport['severity'], file: string, message: string): SuppressionReport {
  return { ruleId, severity, file, line: 1, message };
}

function expired(until: string | null, today: string): boolean {
  return until !== null && DATE.test(until) && until < today;
}

export function auditSuppressions(
  comments: readonly string[],
  findings: readonly LiveFinding[],
  today: string,
): { findings: LiveFinding[]; reports: SuppressionReport[]; comments: readonly string[] } {
  if (!enabled()) {
    return { findings: [...findings], reports: [], comments };
  }
  const reports: SuppressionReport[] = [];
  const hidden = new Set<number>();
  comments.forEach((comment) => {
    const parsed = parseSuppression(comment);
    if (parsed === null) {
      return;
    }
    const hit = findings.findIndex((finding) => finding.ruleId === parsed.ruleId && finding.file === commentFile(comment, findingFile(findings, parsed.ruleId)));
    const file = commentFile(comment, 'suppress');
    if (parsed.bare) {
      reports.push(report(SUPPRESS_BARE, 'medium', file, 'suppression has no usable reason, owner, or YYYY-MM-DD date'));
      return;
    }
    if (hit < 0) {
      reports.push(report(SUPPRESS_ORPHAN, 'info', file, 'suppression matches no current finding'));
      return;
    }
    if (expired(parsed.until, today)) {
      reports.push(report(SUPPRESS_EXPIRED, 'medium', file, 'suppression is past until'));
      return;
    }
    hidden.add(hit);
  });
  return {
    findings: findings.filter((_, index) => !hidden.has(index)),
    reports,
    comments,
  };
}

function findingFile(findings: readonly LiveFinding[], ruleId: string): string {
  return findings.find((finding) => finding.ruleId === ruleId)?.file ?? 'suppress';
}

function commentFile(comment: string, fallback: string): string {
  const match = /file=(\S+)/.exec(comment);
  return match?.[1] ?? fallback;
}
