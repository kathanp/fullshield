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

  it('returns the scan when no path is set and refuses a safe cell', () => {
    process.env[FLAG] = '1';
    const scan = { findings: [{ ruleId: 'SAST-IDOR-002' }, { ruleId: 'SAST-SQLI-001', id: 'z' }, { ruleId: 'SAST-IDOR-002', id: 'a' }] };
    let wrote = false;
    expect(accessReport(scan, routes, { write: () => { wrote = true; } })).toBe(scan);
    expect(wrote).toBe(false);
    const report = buildAccessReport(routes, scan);
    expect(report.findingIds.find((entry) => entry.ruleId === 'SAST-IDOR-002')?.ids).toEqual(['a', 'SAST-IDOR-002']);
    expect(report.findingIds.some((entry) => entry.ruleId === 'SAST-SQLI-001')).toBe(false);
    const safe = { ...routes[0], auth: 'safe', authz: 'none', ownerScope: 'not-computed' };
    expect(() => buildAccessReport([safe], scan)).toThrow(/forbidden cell/);
    expect(() => buildAccessReport([{ ...routes[0], authz: 'safe' }], scan)).toThrow(/forbidden cell/);
    process.env.FULLSHIELD_EXPERIMENTAL_OWNERFLOW = '1';
    expect(() => buildAccessReport([{ ...routes[0], ownerScope: 'safe' }], scan)).toThrow(/forbidden cell/);
    delete process.env.FULLSHIELD_EXPERIMENTAL_OWNERFLOW;
  });
});
