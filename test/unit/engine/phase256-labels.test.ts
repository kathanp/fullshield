import { afterEach, describe, expect, it } from 'vitest';

import {
  LABEL_FLAG,
  SANITIZERS,
  SINK_LABELS,
  applySanitizer,
  labelsEnabled,
  reachesSink,
  sourceLabels,
  sqlConcatReports,
} from '../../../src/engine/labels.js';

afterEach(() => {
  delete process.env[LABEL_FLAG];
});

describe('phase 256 labels', () => {
  it('is off unless the flag is set', () => {
    expect(labelsEnabled()).toBe(false);
    expect(sqlConcatReports('db.query(sql + req.query.id)')).toBe(false);
    process.env[LABEL_FLAG] = '1';
    expect(labelsEnabled()).toBe(true);
  });

  it('runs every sanitizer against every sink label', () => {
    expect(SANITIZERS.length).toBe(30);
    const start = sourceLabels();
    for (const row of SANITIZERS) {
      for (const sink of SINK_LABELS) {
        const kept = applySanitizer(start, row.name);
        expect(kept.has(sink)).toBe(!row.removes.includes(sink));
        expect(reachesSink(row.name, sink)).toBe(!row.removes.includes(sink));
      }
    }
  });

  it('keeps SQL taint through an HTML escape and drops it through Number()', () => {
    process.env[LABEL_FLAG] = '1';
    expect(SANITIZERS.find((row) => row.name === 'DOMPurify')?.removes).toEqual(['xss']);
    expect(SANITIZERS.find((row) => row.name === 'encodeURIComponent')?.removes).toEqual(['redirect', 'ssrf-path']);
    expect(reachesSink('DOMPurify', 'sqli')).toBe(true);
    expect(reachesSink('escapeHtml', 'sqli')).toBe(true);
    expect(reachesSink('Number', 'sqli')).toBe(false);
    expect(reachesSink('z.number', 'sqli')).toBe(false);
    expect(reachesSink('isInt', 'sqli')).toBe(false);
    expect(reachesSink('JSON.parse', 'sqli')).toBe(true);
    expect(reachesSink('z.string', 'sqli')).toBe(true);
    expect(reachesSink('encodeURIComponent', 'redirect')).toBe(false);
    expect(reachesSink('encodeURIComponent', 'ssrf')).toBe(true);
    const withPath = sourceLabels();
    withPath.add('ssrf-path');
    expect(applySanitizer(withPath, 'encodeURIComponent').has('ssrf-path')).toBe(false);
    expect(applySanitizer(withPath, 'encodeURIComponent').has('ssrf')).toBe(true);
    expect(sqlConcatReports('db.query(sql + escapeHtml(req.query.id))')).toBe(true);
    expect(sqlConcatReports('db.query(sql + DOMPurify.sanitize(req.query.id))')).toBe(true);
    expect(sqlConcatReports('db.query(sql + Number(req.query.id))')).toBe(false);
    expect(sqlConcatReports('db.query("select 1")')).toBe(false);
  });
});
