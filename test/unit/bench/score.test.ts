import { describe, expect, it } from 'vitest';

import { classForRule, isTruePositive, scoreFindings } from '../../../src/bench/score.js';

describe('bench score matching', () => {
  it('maps SQLI to sqli and treats line ±3 on the same file as a true positive', () => {
    expect(classForRule('SAST-SQLI-001')).toBe('sqli');
    expect(
      isTruePositive(
        { ruleId: 'SAST-SQLI-001', file: 'core/appHandler.js', line: 12 },
        {
          class: 'sqli',
          file: 'core/appHandler.js',
          line: 10,
          description: 'concat',
          source: 'https://example.test',
        },
      ),
    ).toBe(true);
    expect(
      isTruePositive(
        { ruleId: 'SAST-SQLI-001', file: 'core/appHandler.js', line: 20 },
        {
          class: 'sqli',
          file: 'core/appHandler.js',
          line: 10,
          description: 'concat',
          source: 'https://example.test',
        },
      ),
    ).toBe(false);
  });

  it('maps SECRET/DEPS/CONFIG prefixes and treats path suffixes as the same file', () => {
    expect(classForRule('SECRET-AWS-001')).toBe('secrets');
    expect(classForRule('DEPS-VULN-001')).toBe('deps');
    expect(classForRule('CONFIG-HELMET-001')).toBe('config');
    expect(classForRule('SAST-EVAL-001')).toBe('other');
    expect(
      isTruePositive(
        { ruleId: 'SAST-SSRF-001', file: 'cloned/app/routes/research.js', line: 16 },
        {
          class: 'ssrf',
          file: 'app/routes/research.js',
          line: 16,
          description: 'ssrf',
          source: 'https://example.test',
        },
      ),
    ).toBe(true);
  });

  it('counts unmatched findings as false positives and unmatched truth as misses', () => {
    const scored = scoreFindings(
      [
        { ruleId: 'SAST-CMDI-001', file: 'core/appHandler.js', line: 39 },
        { ruleId: 'CONFIG-HELMET-001', file: 'server.js', line: 1 },
      ],
      [
        {
          class: 'cmdi',
          file: 'core/appHandler.js',
          line: 39,
          description: 'ping',
          source: 'https://example.test',
        },
        {
          class: 'xss',
          file: 'views/xss.ejs',
          line: 4,
          description: 'xss',
          source: 'https://example.test',
        },
      ],
    );
    expect(scored.truePositives).toHaveLength(1);
    expect(scored.misses).toHaveLength(1);
    expect(scored.falsePositives).toHaveLength(1);
  });
});
