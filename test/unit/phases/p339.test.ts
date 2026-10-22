import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p339.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 339', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.sourceMapFindings('a.js', 'sourceMappingURL=https://example.invalid/a.map', []).fetched).toBe(false);
    expect(phase.sourceMapFindings('a.js', 'sourceMappingURL=https://example.invalid/a.map', []).findings).toEqual([]);
  });

  it('reports a remote map without fetching it and ignores a local json map', () => {
    process.env[phase.FLAG] = '1';
    const remote = phase.sourceMapFindings('app.js', '//# sourceMappingURL=https://example.invalid/a.map', []);
    expect(remote.fetched).toBe(false);
    expect(remote.findings[0]?.ruleId).toBe('SECRETS-SRCMAP-001');
    const local = phase.sourceMapFindings('app.js', JSON.stringify({ sources: ['src/a.js'], sourcesContent: ['const a = 1'] }), []);
    expect(local.findings).toEqual([]);
    expect(local.fetched).toBe(false);
  });
});
