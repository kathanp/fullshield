import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p344.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 344', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.managerFindings([{ file: 'a.js', line: 1, callee: 'getSecret', sink: 'response' }], [])).toEqual([]);
    expect(phase.hostsContacted()).toEqual(phase.HOSTS_CONTACTED);
  });

  it('reports a response sink and ignores a sign sink', () => {
    process.env[phase.FLAG] = '1';
    const hit = phase.managerFindings([{ file: 'a.js', line: 2, callee: 'getSecret', sink: 'response' }], []);
    expect(hit[0]?.ruleId).toBe('SECRETS-SECMGR-001');
    expect(phase.managerFindings([{ file: 'a.js', line: 2, callee: 'getSecret', sink: 'sign' }], [])).toEqual([]);
  });

  it('reports a bundle sink and a literal fallback', () => {
    process.env[phase.FLAG] = '1';
    const formats = [{
      id: 'synth', source: 'https://example.invalid/grammar', prefix: 'fsyn_', alphabet: 'A-Za-z0-9', length: 16, notBeforeLength: 21,
      synthetic: [{ value: 'fsyn_ABCDEFGHIJKLMNOP', synthetic: true as const }],
    }];
    const flows = [
      { file: 'a.js', line: 1, callee: 'getSecretValue', sink: 'bundle' as const },
      { file: 'a.js', line: 2, callee: 'GetSecretValueCommand', sink: 'none' as const, fallbackLiteral: 'fsyn_ABCDEFGHIJKLMNOP' },
      { file: 'a.js', line: 3, callee: 'accessSecretVersion', sink: 'sign' as const, fallbackLiteral: 'plain' },
      { file: 'a.js', line: 4, callee: 'vault.read', sink: 'response' as const },
      { file: 'a.js', line: 5, callee: 'localRead', sink: 'response' as const },
    ];
    const findings = phase.managerFindings(flows, formats);
    expect(findings.map((finding) => finding.ruleId)).toEqual(['SECRETS-SECMGR-001', 'SECRETS-FORMAT-001', 'SECRETS-SECMGR-001']);
    expect(phase.hostsContacted()).toEqual([]);
  });
});
