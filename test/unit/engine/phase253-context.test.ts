import { afterEach, describe, expect, it } from 'vitest';

import { CONTEXT_FLAG, contextEnabled, contextFindings } from '../../../src/engine/summaries.js';

afterEach(() => {
  delete process.env[CONTEXT_FLAG];
});

function chain(hops: number): string {
  const lines = [`function f${hops}(a){ db.query(a); }`];
  for (let hop = hops - 1; hop >= 1; hop -= 1) {
    lines.push(`function f${hop}(a){ f${hop + 1}(a); }`);
  }
  lines.push('f1(req.query.x);');
  return lines.join('\n');
}

describe('phase 253 context', () => {
  it('is off unless the flag is set', () => {
    expect(contextEnabled()).toBe(false);
    expect(contextFindings(chain(7))).toEqual([]);
  });

  it('finds a 7-hop chain and only the tainted call of a shared helper', () => {
    process.env[CONTEXT_FLAG] = '1';
    expect(contextFindings(chain(7))).toEqual([{ line: 8, callee: 'f1' }]);
    const shared = [
      'function helper(x){ db.query(x); }',
      'helper(req.body.x);',
      'helper("literal");',
    ].join('\n');
    const findings = contextFindings(shared);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.callee).toBe('helper');
  });

  it('terminates on recursion and stays sound past the fixpoint cap', () => {
    process.env[CONTEXT_FLAG] = '1';
    const recursive = 'function rec(x){ rec(x); db.query(x); }\nrec(req.query.x);\n';
    expect(contextFindings(recursive)).toHaveLength(1);
    expect(contextFindings(chain(12), 3).length).toBeGreaterThan(0);
  });
});
