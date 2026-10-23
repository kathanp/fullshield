import { afterEach, describe, expect, it } from 'vitest';

import { enabled, explainMatrix, FLAG, OWNER_FLAG, withMatrix, type MatrixRoute } from '../../../src/phases/p313.js';

const routes: MatrixRoute[] = [
  { method: 'GET', path: '/public', file: 'a.js', auth: 'none', authz: 'none', sinks: ['http'], message: 'SAST-IDOR-002 object' },
  { method: 'POST', path: '/admin', file: 'b.js', auth: 'session', authz: 'role', sinks: ['db'] },
  { method: 'GET', path: '/me', file: 'c.js', auth: 'unknown', authz: 'none', sinks: [] },
];

afterEach(() => {
  delete process.env[FLAG];
  delete process.env[OWNER_FLAG];
});

describe('phase 313 access matrix', () => {
  it('leaves scan JSON unchanged when the flag is off', () => {
    const scan = { findings: [{ ruleId: 'SAST-SQLI-001' }] };
    expect(enabled()).toBe(false);
    expect(withMatrix(scan, routes)).toBe(scan);
    expect('matrix' in withMatrix(scan, routes)).toBe(false);
  });

  it('prints three rows and keeps unknown', () => {
    process.env[FLAG] = '1';
    const scan = { findings: [{ ruleId: 'SAST-SQLI-001', message: 'sql' }] };
    const next = withMatrix(scan, routes);
    expect(next.findings).toBe(scan.findings);
    expect(next.matrix).toHaveLength(3);
    expect(next.matrix?.map((row) => row.auth)).toContain('unknown');
    expect(next.matrix?.every((row) => row.ownerScope === 'not-computed')).toBe(true);
    expect(JSON.stringify(next.matrix)).not.toContain('SAST-IDOR-002');
    expect(explainMatrix(routes)).toContain('method path auth authz owner-scope sinks');
    expect(explainMatrix(routes).split('\n')).toHaveLength(4);
  });
});
