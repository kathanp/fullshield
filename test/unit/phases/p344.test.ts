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
});
