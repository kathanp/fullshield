import { describe, expect, it } from 'vitest';

import type { Finding } from '../../../src/core/finding.js';
import { ExplainError, matchFinding, renderExplain } from '../../../src/explain/index.js';

function finding(id: string, extra: Partial<Finding> = {}): Finding {
  return {
    id,
    ruleId: 'SAST-SQLI-001',
    module: 'sast',
    title: 'SQL injection',
    severity: 'high',
    confidence: 'high',
    file: 'a.js',
    line: 2,
    message: 'tainted',
    remediation: 'use a parameter',
    ...extra,
  };
}

describe('phase 60 explain', () => {
  it('prints a trace, a dependency path, and a masked secret', () => {
    const traced = renderExplain(
      finding('abcdef123456', {
        trace: [
          { file: 'a.js', line: 1, note: 'source' },
          { file: 'b.js', line: 2, note: 'helper' },
          { file: 'c.js', line: 3, note: 'sink' },
        ],
      }),
      'const q = req.query.id\nconst sql = q\ndb.query(sql)\n',
    );
    expect(traced).toContain('a.js:1 source');
    expect(traced).toContain('c.js:3 sink');
    expect(traced).toContain('rules/SAST-SQLI-001.md');
    const dep = renderExplain(
      finding('abcdef123456', {
        ruleId: 'DEPS-VULN-001',
        module: 'deps',
        reachability: 'reachable',
        dependencyPath: ['express', 'qs'],
        snippet: 'qs@6.5.2',
      }),
    );
    expect(dep).toContain('reachability: reachable (express > qs)');
    const secret = renderExplain(
      finding('abcdef123456', { ruleId: 'SECRET-AWS-001', module: 'secrets', snippet: 'AKIA****' }),
    );
    expect(secret).toContain('AKIA****');
    expect(secret).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('rejects a short, missing, or ambiguous prefix', () => {
    const findings = [finding('abcdef111111'), finding('abcdef222222')];
    expect(() => matchFinding(findings, 'abc')).toThrow(ExplainError);
    expect(() => matchFinding(findings, 'zzzzzz')).toThrow(/no finding matches/);
    expect(() => matchFinding(findings, 'abcdef')).toThrow(/ambiguous id/);
    expect(matchFinding(findings, 'abcdef111111').id).toBe('abcdef111111');
  });

  it('does not call the network', () => {
    const original = globalThis.fetch;
    globalThis.fetch = () => {
      throw new Error('network');
    };
    try {
      expect(renderExplain(finding('abcdef123456'))).toContain('SAST-SQLI-001');
    } finally {
      globalThis.fetch = original;
    }
  });
});
