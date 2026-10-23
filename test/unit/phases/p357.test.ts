import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p357.js';
import { FLAG as SCRIPT } from '../../../src/phases/p353.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 357', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.capabilityFindings('left', "fs.writeFileSync('/tmp/x')", { draft: false, packages: {} })).toEqual([]);
  });

  it('reports a capability outside the policy and stays quiet for a draft', () => {
    process.env[phase.FLAG] = '1';
    process.env[SCRIPT] = '1';
    const hit = phase.capabilityFindings('left', "fs.writeFileSync('/tmp/x')", { draft: false, packages: {} });
    expect(hit[0]?.effect).toBe('fs-write');
    expect(hit[0]?.message).toContain('may');
    expect(phase.capabilityFindings('left', "fs.writeFileSync('/tmp/x')", { draft: true, packages: {} })).toEqual([]);
    expect(phase.policyInit(['fs-write']).draft).toBe(true);
    delete process.env[SCRIPT];
  });
});
