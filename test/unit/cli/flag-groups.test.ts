import { describe, expect, it } from 'vitest';

import { applyFlagGroups } from '../../../src/core/flag-groups.js';

describe('experimental flag groups', () => {
  it('turns on unset sast, runtime, report, and ai members', () => {
    const env: NodeJS.ProcessEnv = {
      FULLSHIELD_EXPERIMENTAL_SAST_EXTRA: '1',
      FULLSHIELD_EXPERIMENTAL_RUNTIME: '1',
      FULLSHIELD_EXPERIMENTAL_REPORTS: '1',
      FULLSHIELD_EXPERIMENTAL_AI: '1',
      FULLSHIELD_EXPERIMENTAL_SECTIONG: '0',
    };
    applyFlagGroups(env);
    expect(env.FULLSHIELD_EXPERIMENTAL_SECTIONG).toBe('0');
    expect(env.FULLSHIELD_EXPERIMENTAL_LDAP).toBe('1');
    expect(env.FULLSHIELD_EXPERIMENTAL_RASP).toBe('1');
    expect(env.FULLSHIELD_EXPERIMENTAL_SARIF_V2).toBe('1');
    expect(env.FULLSHIELD_EXPERIMENTAL_LLM).toBe('1');
    expect(env.FULLSHIELD_EXPERIMENTAL_AGENTRULES).toBe('1');
    expect(env.FULLSHIELD_EXPERIMENTAL_MCPPOISON).toBe('1');
    expect(env.FULLSHIELD_EXPERIMENTAL_PROVENANCE).toBeUndefined();
  });

  it('does nothing when the group flags are unset', () => {
    const env: NodeJS.ProcessEnv = {};
    applyFlagGroups(env);
    expect(env.FULLSHIELD_EXPERIMENTAL_LDAP).toBeUndefined();
    expect(env.FULLSHIELD_EXPERIMENTAL_RASP).toBeUndefined();
  });

  it('fans out the supply group and leaves an explicit member value', () => {
    const env: NodeJS.ProcessEnv = {
      FULLSHIELD_EXPERIMENTAL_SUPPLY: '1',
      FULLSHIELD_EXPERIMENTAL_NPM_FLOAT: '0',
    };
    applyFlagGroups(env);
    expect(env.FULLSHIELD_EXPERIMENTAL_PROVENANCE).toBe('1');
    expect(env.FULLSHIELD_EXPERIMENTAL_NPM_FLOAT).toBe('0');
  });
});
