import { afterEach, describe, expect, it } from 'vitest';

import {
  auditSuppressions,
  enabled,
  FLAG,
  SUPPRESS_BARE,
  SUPPRESS_EXPIRED,
  SUPPRESS_ORPHAN,
  type LiveFinding,
} from '../../../src/phases/p429.js';

afterEach(() => {
  delete process.env[FLAG];
});

const finding: LiveFinding = {
  ruleId: 'SAST-SQLI-001',
  file: 'src/a.js',
  line: 3,
  severity: 'high',
  message: 'sink',
};

function comment(body: string): string {
  return `// fullshield-suppress ${body}`;
}

describe('phase 429 suppression audit', () => {
  it('returns findings and comments unchanged when the flag is off', () => {
    expect(enabled()).toBe(false);
    const comments = [comment('SAST-SQLI-001')];
    const result = auditSuppressions(comments, [finding], '2026-10-22');
    expect(result.reports).toEqual([]);
    expect(result.findings).toEqual([finding]);
    expect(result.comments).toBe(comments);
  });

  it('hides a dated suppression and keeps the comment', () => {
    process.env[FLAG] = '1';
    const comments = [comment('SAST-SQLI-001 reason="tracked" owner=sec until=2026-12-31 file=src/a.js')];
    const result = auditSuppressions(comments, [finding], '2026-10-22');
    expect(result.findings).toEqual([]);
    expect(result.reports).toEqual([]);
    expect(result.comments).toBe(comments);
  });

  it('reports a bare, orphan, and expired suppression without hiding the finding', () => {
    process.env[FLAG] = '1';
    const comments = [
      comment('SAST-SQLI-001 file=src/a.js'),
      comment('SAST-XSS-001 reason="gone" owner=sec until=2026-12-31 file=src/a.js'),
      comment('SAST-SQLI-001 reason="old" owner=sec until=2020-01-01 file=src/a.js'),
    ];
    const result = auditSuppressions(comments, [finding], '2026-10-22');
    expect(result.findings).toEqual([finding]);
    expect(result.comments).toBe(comments);
    expect(result.reports.map((row) => row.ruleId)).toEqual([SUPPRESS_BARE, SUPPRESS_ORPHAN, SUPPRESS_EXPIRED]);
    expect(result.reports[0]?.severity).toBe('medium');
    expect(result.reports[1]?.severity).toBe('info');
    expect(result.reports[2]?.severity).toBe('medium');
    expect(result.reports[0]?.file).toBe('src/a.js');
  });
});
