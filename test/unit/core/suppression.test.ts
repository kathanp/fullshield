import { describe, expect, it } from 'vitest';

import { applyInlineSuppressions } from '../../../src/core/suppression.js';
import { makeFindingId, type Finding } from '../../../src/core/finding.js';

function finding(ruleId: string, file: string, line: number): Finding {
  return {
    id: makeFindingId(ruleId, file, `${line}`),
    ruleId,
    module: 'sast',
    title: ruleId,
    severity: 'high',
    confidence: 'high',
    file,
    line,
    message: ruleId,
    remediation: 'fix',
  };
}

describe('inline fullshield-ignore', () => {
  it('suppresses the next line when a reason is present', () => {
    const source = {
      'src/a.js': `// fullshield-ignore SAST-SQLI-001: parameterized in review\n db.query(x + y);\n`,
    };
    const out = applyInlineSuppressions([finding('SAST-SQLI-001', 'src/a.js', 2)], source);
    expect(out).toEqual([]);
  });

  it('does not suppress without a reason or for a different rule', () => {
    const source = {
      'src/a.js': `// fullshield-ignore SAST-SQLI-001\n db.query(x + y);\n`,
    };
    const sql = finding('SAST-SQLI-001', 'src/a.js', 2);
    expect(applyInlineSuppressions([sql], source)).toEqual([sql]);

    const reasoned = {
      'src/a.js': `// fullshield-ignore SAST-SQLI-001: ok for now\n eval(z);\n`,
    };
    const ev = finding('SAST-EVAL-001', 'src/a.js', 2);
    expect(applyInlineSuppressions([ev], reasoned)).toEqual([ev]);
  });
});
