import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { applyBaseline } from '../../../src/core/baseline.js';
import { diffNewFindings } from '../../../src/core/watch.js';
import { makeFindingId, type Finding } from '../../../src/core/finding.js';
import { renderPrSummary, ruleDocsUrl } from '../../../src/policy/prSummary.js';

const goldens = join(process.cwd(), 'test', 'fixtures', 'policy');

function readGolden(name: string): string {
  return readFileSync(join(goldens, name), 'utf8').replaceAll('\r\n', '\n');
}

function finding(ruleId: string, overrides: Partial<Finding> = {}): Finding {
  const file = overrides.file ?? 'src/a.js';
  return {
    id: makeFindingId(ruleId, file, overrides.snippet ?? ruleId),
    ruleId,
    module: 'sast',
    title: ruleId,
    severity: 'high',
    confidence: 'high',
    file,
    line: 1,
    message: `${ruleId} message`,
    remediation: 'fix',
    ...overrides,
  };
}

const sqli = finding('SAST-SQLI-001', {
  module: 'sast',
  severity: 'high',
  file: 'src/db.js',
  line: 12,
  message: 'Tainted input concatenated into a SQL query.',
});

const helmet = finding('CONFIG-HELMET-001', {
  module: 'config',
  severity: 'medium',
  file: 'src/app.js',
  line: 4,
  message: 'Express app is missing helmet().',
});

describe('renderPrSummary', () => {
  it('matches the two-finding golden file', () => {
    const expected = readGolden('pr-summary.md');
    expect(renderPrSummary([helmet, sqli])).toBe(expected);
  });

  it('matches the empty golden file', () => {
    const expected = readGolden('pr-summary-empty.md');
    expect(renderPrSummary([])).toBe(expected);
  });

  it('is deterministic across calls and omits AI fields', () => {
    const withAi: Finding = {
      ...sqli,
      source: 'ai',
      explanation: 'an LLM wrote this',
      aiVerdict: 'likely-false-positive',
    };
    const first = renderPrSummary([helmet, sqli, withAi]);
    const second = renderPrSummary([withAi, sqli, helmet]);
    expect(first).toBe(second);
    expect(first).toBe(readGolden('pr-summary.md'));
    expect(first).not.toMatch(/likely-false-positive|an LLM wrote this|openai|anthropic/i);
  });

  it('lists only findings that are new versus baseline / last-scan ids', () => {
    const remaining = applyBaseline([sqli, helmet], {
      version: 1,
      findings: [{ id: helmet.id, ruleId: helmet.ruleId, file: helmet.file, line: helmet.line }],
    });
    const md = renderPrSummary(remaining);
    expect(md).toContain('SAST-SQLI-001');
    expect(md).not.toContain('CONFIG-HELMET-001');
    expect(md).toContain('1 new finding(s) versus baseline');

    const fromDiff = diffNewFindings([sqli, helmet], new Set([helmet.id]));
    expect(renderPrSummary(fromDiff)).toBe(md);
  });

  it('links each rule id to the shipped rule doc on GitHub', () => {
    expect(ruleDocsUrl('SAST-SQLI-001')).toBe(
      'https://github.com/kathanp/fullshield/blob/main/rules/SAST-SQLI-001.md',
    );
    const md = renderPrSummary([sqli]);
    expect(md).toContain(ruleDocsUrl('SAST-SQLI-001'));
  });
});
