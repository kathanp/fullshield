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
});
