import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p284.js';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 284', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeRedos('const re = /a/;').findings).toEqual([]);
  });

  it('parses an atom and does not flag a single literal class', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.parsePattern('a').type).toBe('atom');
    expect(phase.analyzeRedos('const re = /a/;').findings).toEqual([]);
  });

  it('parses quantifiers, classes, and reports a nested repeat', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeRedos(':::').findings).toEqual([]);
    expect(phase.parsePattern('\\1').type).toBe('unknown');
    expect(phase.parsePattern('(?<=a)').type).toBe('unknown');
    expect(phase.parsePattern('a|b').type).toBe('alt');
    expect(phase.parsePattern('').type).toBe('eps');
    expect(phase.parsePattern('a*').type).toBe('rep');
    expect(phase.parsePattern('a+').type).toBe('rep');
    expect(phase.parsePattern('a?').type).toBe('rep');
    expect(phase.parsePattern('a{2}').type).toBe('rep');
    expect(phase.parsePattern('a{2,}').type).toBe('rep');
    expect(phase.parsePattern('a{2,4}').type).toBe('rep');
    expect(phase.parsePattern('a{').type).toBe('cat');
    expect(phase.parsePattern('^$').type).toBe('cat');
    expect(phase.parsePattern('^').type).toBe('eps');
    expect(phase.parsePattern('.').type).toBe('atom');
    expect(phase.parsePattern('\\d\\w\\s\\.').type).toBe('cat');
    expect(phase.parsePattern('[0-9]').type).toBe('atom');
    expect(phase.parsePattern('[a-zA-Z]').type).toBe('atom');
    expect(phase.parsePattern('[abc]').type).toBe('atom');
    expect(phase.parsePattern('[').type).toBe('atom');
    expect(phase.parsePattern('(a)').type).toBe('atom');
    expect(phase.parsePattern('(?:a)').type).toBe('atom');
    expect(phase.parsePattern('(?<name>a)').type).toBe('atom');
    expect(phase.parsePattern('(a*)*').type).toBe('rep');
    const source = [
      'const re = /(a+)+$/;',
      'const named = /a*a*/;',
      'const built = new RegExp("(a+)+");',
      'function check(input) {',
      '  re.test(input);',
      '  named.exec(req.query.id);',
      '  input.match(re);',
      '  input.replace(named, "");',
      '  input.split(built);',
      '  Number(req.query.id).match(/[a-z]+/);',
      '  if (input.length < 10) { re.test(input); }',
      '}',
    ].join('\n');
    expect(phase.analyzeRedos(source).findings.length).toBeGreaterThan(0);
    delete process.env[phase.FLAG];
  });
});
