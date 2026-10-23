import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p281.js';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 281', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeUrl('fetch(req.query.url);').findings).toEqual([]);
  });

  it('reports a request fetch and ignores a literal url', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeUrl('fetch(req.query.url);').findings.length).toBeGreaterThan(0);
    expect(phase.analyzeUrl('fetch("https://example.invalid/a");').findings).toEqual([]);
  });

  it('classifies path, query, fragment, and URL constructors', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeUrl(':::').findings).toEqual([]);
    const source = [
      'function f(req) {',
      '  fetch(req.query.x);',
      '  http.get("https://ex/" + req.query.x);',
      '  fetch("https://ex" + req.query.x);',
      '  fetch("https://ex/a?q=" + req.query.x);',
      '  fetch("https://ex/a#f" + req.query.x);',
      '  new URL(req.query.x);',
      '  new URL(Number(req.query.x));',
      '  new URL(Number(req.query.x), "https://ex/a/");',
      '  fetch(mystery(req.query.x));',
      '  fetch(other[name](req.query.x));',
      '  notASink(req.query.x);',
      '  new URL(...args);',
      '  if (cond) { fetch(req.query.x); } else fetch(req.query.y);',
      '  const u = "https://ex/" + req.query.x;',
      '  request(u);',
      '  fetch(...args);',
      '}',
    ].join('\n');
    const contexts = phase.analyzeUrl(source).findings.map((row) => row.ssrfContext);
    expect(contexts).toContain('path');
    expect(contexts).toContain('query');
    expect(contexts).toContain('fragment');
    delete process.env[phase.FLAG];
  });
});
