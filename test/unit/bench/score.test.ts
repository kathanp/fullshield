import { describe, expect, it } from 'vitest';

import {
  classForRule,
  isTruePositive,
  precisionFromTriage,
  scoreFindings,
} from '../../../src/bench/score.js';

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
          inScope: true,
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
          inScope: true,
        },
      ),
    ).toBe(false);
  });

  it('maps EVAL/JWT/CRYPTO/PROTO and SECRET/DEPS/CONFIG prefixes; path suffixes match', () => {
    expect(classForRule('SAST-EVAL-001')).toBe('eval');
    expect(classForRule('SAST-JWT-001')).toBe('jwt');
    expect(classForRule('SAST-CRYPTO-001')).toBe('crypto');
    expect(classForRule('SAST-PROTO-001')).toBe('proto');
    expect(classForRule('SECRET-AWS-001')).toBe('secrets');
    expect(classForRule('DEPS-VULN-001')).toBe('deps');
    expect(classForRule('CONFIG-HELMET-001')).toBe('config');
    expect(
      isTruePositive(
        { ruleId: 'SAST-SSRF-001', file: 'cloned/app/routes/research.js', line: 16 },
        {
          class: 'ssrf',
          file: 'app/routes/research.js',
          line: 16,
          description: 'ssrf',
          source: 'https://example.test',
          inScope: true,
        },
      ),
    ).toBe(true);
  });

  it('counts recall only on inScope entries; unmatched findings are not auto-FP', () => {
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
          inScope: true,
        },
        {
          class: 'xss',
          file: 'views/xss.ejs',
          line: 4,
          description: 'xss',
          source: 'https://example.test',
          inScope: true,
        },
        {
          class: 'other',
          file: 'core/appHandler.js',
          line: 218,
          description: 'deser',
          source: 'https://example.test',
          inScope: false,
          reason: 'deserialization is Phase 29',
        },
      ],
    );
    expect(scored.truePositives).toHaveLength(1);
    expect(scored.inScopeMisses).toHaveLength(1);
    expect(scored.outOfScope).toHaveLength(1);
    expect(scored.unmatched).toHaveLength(1);
    expect(scored.unmatched[0]?.ruleId).toBe('CONFIG-HELMET-001');
  });

  it('computes precision from triage verdicts and counts unsure separately', () => {
    const prec = precisionFromTriage([
      { verdict: 'falsePositive', reason: 'docs example' },
      { verdict: 'falsePositive', reason: 'tutorial HTML' },
      { verdict: 'realIssue', reason: 'OSV hit' },
      { verdict: 'unsure', reason: 'needs human' },
    ]);
    expect(prec.falsePositive).toBe(2);
    expect(prec.realIssue).toBe(1);
    expect(prec.unsure).toBe(1);
    expect(prec.precision).toBe('33.3%');
  });
});
