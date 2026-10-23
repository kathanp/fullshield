import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p286.js';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 286', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeRoundTrip('db.query("1");').findings).toEqual([]);
  });

  it('does not report a literal query', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeRoundTrip('db.query("select 1");').findings).toEqual([]);
  });

  it('keeps a field through JSON and restores a decoded value', () => {
    process.env[phase.FLAG] = '1';
    const field = phase.analyzeRoundTrip(`function f(req) {
      const o = { a: req.query.a };
      const back = JSON.parse(JSON.stringify(o));
      db.query(back.a);
    }`);
    expect(field.findings[0]).toMatchObject({ field: 'a', labels: ['sqli'] });
    const decoded = phase.analyzeRoundTrip(`function f(req) {
      const s = encodeURIComponent(req.query.x);
      db.query(decodeURIComponent(s));
    }`);
    expect(decoded.findings).toHaveLength(1);
  });

  it('round-trips buffers, query strings, clones, and compression', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeRoundTrip(':::').findings).toEqual([]);
    const source = [
      'function f(req) {',
      '  const raw = req.query.x;',
      '  const packed = JSON.stringify({ a: raw, skip: 1 });',
      '  const back = JSON.parse(packed);',
      '  const cloned = structuredClone(back);',
      '  const qs = querystring.stringify(cloned);',
      '  const parsed = qs.parse(qs);',
      '  const buf = Buffer.from(parsed);',
      '  const text = buf.toString();',
      '  const zip = gzipSync(text);',
      '  const plain = gunzipSync(zip);',
      '  const deflated = deflateSync(plain);',
      '  const inflated = inflateSync(deflated);',
      '  const hidden = btoa(inflated);',
      '  const shown = atob(hidden);',
      '  db.query(shown);',
      '  res.send(back.a);',
      '  exec(raw + "x");',
      '  if (cond) { db.query(raw); } else { db.query("1"); }',
      '  { db.query(missing); }',
      '}',
    ].join('\n');
    expect(phase.analyzeRoundTrip(source).findings.length).toBeGreaterThan(0);
    delete process.env[phase.FLAG];
  });
});
