import { afterEach, describe, expect, it } from 'vitest';

import { accessReport, buildAccessReport, enabled, FLAG, HEADER } from '../../../src/phases/p330.js';
import type { MatrixRoute } from '../../../src/phases/p313.js';

const routes: MatrixRoute[] = [
  { method: 'GET', path: '/x', file: 'a.js', auth: 'unknown', authz: 'none', sinks: [] },
];

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 330 access report', () => {
  it('fails the option and does not write when the flag is off', () => {
    const scan = { findings: [{ ruleId: 'SAST-SQLI-001', id: '1' }] };
    let wrote = false;
    expect(enabled()).toBe(false);
    expect(() => accessReport(scan, routes, { path: 'out.json', write: () => { wrote = true; } })).toThrow(/FS-E330/);
    expect(wrote).toBe(false);
    expect(accessReport(scan, routes)).toBe(scan);
  });

  it('writes a snapshot whose unknown cell stays unknown', () => {
    process.env[FLAG] = '1';
    const scan = { findings: [{ ruleId: 'SAST-IDOR-002', id: 'idor' }] };
    let body = '';
    expect(accessReport(scan, routes, { path: 'out.json', write: (_path, text) => { body = text; } })).toBe(scan);
    const report = buildAccessReport(routes, scan);
    expect(body).toBe(JSON.stringify(report));
    expect(report.header).toBe(HEADER);
    expect(report.rows[0]?.auth).toBe('unknown');
    expect(JSON.stringify(report)).not.toContain('"safe"');
  });
});
