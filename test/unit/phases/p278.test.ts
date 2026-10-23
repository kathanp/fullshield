import { afterEach, describe, expect, it } from 'vitest';

import { parseProgram, walkAst } from '../../../src/phases/p271.js';
import * as phase from '../../../src/phases/p278.js';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 278', () => {
  it('does not evaluate when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.evaluateProgram('function run() { return "a"; }')).toBeNull();
  });

  it('concatenates abstract strings and keeps a literal free of taint labels', () => {
    process.env[phase.FLAG] = '1';
    const joined = phase.concatAbs(phase.lit('a'), phase.tainted(['req'], 'any'));
    expect(phase.labelsOf(joined)).toContain('req');
    expect(phase.labelsOf(phase.lit('safe'))).toEqual([]);
  });

  it('evaluates string operations, loops, and a segment overflow', () => {
    expect(phase.concatAbs(phase.lit('a'), phase.lit('b')).segments).toEqual([{ kind: 'literal', text: 'a' }]);
    const program = parseProgram('function f() { return value.join(","); }');
    let call: TSESTree.CallExpression | undefined;
    if (program !== null) {
      walkAst(program, (node) => {
        if (node.type === 'CallExpression') {call = node;}
      });
    }
    if (call !== undefined) {expect(phase.abstractExpression(call, new Map()).segments).toEqual([]);}
    process.env[phase.FLAG] = '1';
    expect(phase.evaluateProgram(':::')).toBeNull();
    expect(phase.evaluateProgram('function f() { const x = 1; }')?.segments).toEqual([]);
    const source = [
      'function f() {',
      '  let s = "a" + req.query.x;',
      '  s = s.toUpperCase().toLowerCase();',
      '  s = s.slice(1).substring(0);',
      '  s = s.replace("a", "b");',
      '  s = s.replace(/[\'"]/g, "");',
      '  s = s.replace(/a/g, "");',
      '  s = Number(s);',
      '  s = parseInt(s);',
      '  s = String(req.query.x);',
      '  const joined = ["a", req.query.x].join("-");',
      '  const open = ["a"].join(req.query.x);',
      '  if (cond) { s = "b"; } else { s = req.query.y; }',
      '  for (let i = 0; i < 2; i++) { s = s + req.query.x; }',
      '  while (cond) { s = s + "z"; }',
      '  const text = `pre${req.query.x}post`;',
      '  const replaced = ("a" + req.query.x).replace("a", "b");',
      '  const plain = "ab".replace("cd", "ef");',
      '  const sliced = "abcd".slice(1);',
      '  const merged = "ab" + "cd";',
      '  const field = s.foo;',
      '  mystery(req.query.x);',
      '  for (i = 0; i < 1; i++) { s = s + "z"; }',
      '  return text;',
      '}',
    ].join('\n');
    expect(phase.labelsOf(phase.evaluateProgram(source) ?? phase.lit(''))).toContain('sqli');
    const bindings = Object.fromEntries(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'].map((name) => [name, { labels: ['sqli'], charClass: 'any' as const }]));
    const wide = phase.evaluateProgram('function f() { return a+b+c+d+e+f+g+h+i; }', { bindings });
    expect(wide?.segments[0]?.kind).toBe('unknown');
    delete process.env[phase.FLAG];
  });
});
