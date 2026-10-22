import { describe, expect, it } from 'vitest';

import { FLAG, PROXY_RULE, PROXY_SENTENCE, scanProxyPair } from '../../../src/phases/p459.js';

const trust = "app.set('trust proxy', true);";
const append = 'proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;';
const overwrite = 'proxy_set_header X-Forwarded-For $remote_addr;';

describe('phase 459', () => {
  it('reports append plus trust', () => {
    process.env[FLAG] = '1';
    const findings = scanProxyPair(trust, append);
    expect(findings.some((row) => row.ruleId === PROXY_RULE && row.severity === 'high')).toBe(true);
    expect(findings[0]?.message).toContain(PROXY_SENTENCE);
  });

  it('emits nothing for overwrite, trust alone, or a proxy file alone', () => {
    process.env[FLAG] = '1';
    expect(scanProxyPair(trust, overwrite)).toEqual([]);
    expect(scanProxyPair(trust, null)).toEqual([]);
    expect(scanProxyPair(null, append)).toEqual([]);
  });

  it('returns the baseline when the flag is off', () => {
    const baseline = [{ ruleId: 'kept', severity: 'high' as const, file: 'nginx.conf', line: 1, message: 'kept' }];
    expect(scanProxyPair(trust, append, 'nginx.conf', baseline)).toEqual(baseline);
  });
});
