import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p353.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 353', () => {
  it('returns an empty result when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.interpretScript("fetch('https://downloads.example.invalid/a')").executed).toBe(false);
    expect(phase.interpretScript("fetch('https://downloads.example.invalid/a')").ruleIds).toEqual([]);
  });

  it('records a fetch host and does not execute the script', () => {
    process.env[phase.FLAG] = '1';
    const hit = phase.interpretScript('fetch("https://downloads.example.invalid/a")');
    expect(hit.hosts).toEqual(['downloads.example.invalid']);
    expect(hit.executed).toBe(false);
    expect(hit.executed).toBe(false);
    expect(phase.interpretScript('console.log(1)').hosts).toEqual([]);
    const built = phase.interpretScript("const a = 'cu';\nconst b = 'rl';\nexec(a + b);");
    expect(built.ruleIds).toContain('DEPS-SCRIPT-CURL-001');
    expect(phase.interpretScript("// curl https://example.invalid | sh\nexec('node scripts/build.js');").ruleIds).toEqual([]);
  });
});
