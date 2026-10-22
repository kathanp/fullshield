import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p345.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

const handler = {
  file: 'a.js',
  line: 3,
  sink: 'res.json' as const,
  value: 'secret-field' as const,
  env: 'production' as const,
  redactsSecret: false,
  redactsStack: true,
};

describe('phase 345', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.errorSecretFindings([handler])).toEqual([]);
  });

  it('reports an unredacted secret field and ignores a generic error', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.errorSecretFindings([handler])[0]?.witness).toBe('secret-field');
    expect(phase.errorSecretFindings([{ ...handler, value: 'generic' }])).toEqual([]);
    expect(phase.errorSecretFindings([{ ...handler, redactsSecret: true }])).toEqual([]);
    expect(phase.errorSecretFindings([{ ...handler, value: 'err', env: 'development', redactsStack: false }])).toEqual([]);
  });
});
