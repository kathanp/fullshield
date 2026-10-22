import { describe, expect, it } from 'vitest';

import { changedView, FLAG, PARTIAL_HEADER } from '../../../src/phases/p446.js';

const oldFinding = { ruleId: 'SAST-SQLI-001', file: 'old.js', line: 2, severity: 'high', fingerprint: 'old' };
const newSink = { ruleId: 'SAST-SQLI-001', file: 'app.js', line: 3, severity: 'high', fingerprint: 'sink' };
const oldSink = { ruleId: 'SAST-SQLI-001', file: 'sink.js', line: 9, severity: 'high', fingerprint: 'flow' };
const findings = [oldFinding, newSink, oldSink];
const baseline = JSON.stringify({ marker: 'baseline', findings });

const diff = [
  'diff --git a/app.js b/app.js',
  '--- a/app.js',
  '+++ b/app.js',
  '@@ -1,2 +1,3 @@',
  ' const db = require("db");',
  ' const id = req.query.id;',
  "+db.query('SELECT ' + id);",
  'diff --git a/src.js b/src.js',
  '--- a/src.js',
  '+++ b/src.js',
  '@@ -1,2 +1,3 @@',
  ' function handler() {',
  '+const id = req.query.id;',
  ' return id;',
].join('\n');

describe('phase 446', () => {
  it('includes a new sink and a witness step on an added line', () => {
    process.env[FLAG] = '1';
    const result = changedView(findings, [{ fingerprint: 'flow', file: 'src.js', line: 2 }], diff, baseline, false);
    const shown = JSON.parse(result.json) as Array<{ fingerprint: string }>;
    expect(shown.map((row) => row.fingerprint).sort()).toEqual(['flow', 'sink']);
    expect(result.header).toBe(PARTIAL_HEADER);
  });

  it('omits an untouched file and keeps both in the full document', () => {
    process.env[FLAG] = '1';
    const result = changedView(findings, [{ fingerprint: 'flow', file: 'src.js', line: 2 }], diff, baseline, true);
    const shown = JSON.parse(result.json) as Array<{ fingerprint: string }>;
    expect(shown.map((row) => row.fingerprint)).toContain('old');
    expect(result.fullJson).toContain('old');
  });

  it('stays byte-identical without --changed and when the flag is off', () => {
    process.env[FLAG] = '1';
    expect(changedView(findings, [], undefined, baseline, false).json).toBe(baseline);
    delete process.env[FLAG];
    expect(changedView(findings, [], diff, baseline, false).json).toBe(baseline);
  });
});
