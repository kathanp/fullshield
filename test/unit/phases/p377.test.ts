import { describe, expect, it } from 'vitest';

import { duplicateAdvisories, enabled, FLAG, type VulnRow } from '../../../src/phases/p377.js';

const vuln: VulnRow = { ruleId: 'DEPS-VULN-001', name: 'left-pad', version: '1.0.0', advisoryId: 'FIXTURE-OSV-1' };

describe('phase 377 duplicate advisories', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    const result = duplicateAdvisories(
      [
        { name: 'left-pad', version: '1.0.0', lockPath: 'node_modules/left-pad', advisoryIds: ['FIXTURE-OSV-1'] },
        { name: 'left-pad', version: '1.1.0', lockPath: 'node_modules/app/node_modules/left-pad', advisoryIds: [] },
      ],
      [vuln],
    );
    expect(result.findings).toEqual([]);
    expect(result.vulns).toEqual([vuln]);
  });

  it('reports the symmetric difference and keeps DEPS-VULN-001', () => {
    process.env[FLAG] = '1';
    const result = duplicateAdvisories(
      [
        { name: 'left-pad', version: '1.0.0', lockPath: 'a', advisoryIds: ['FIXTURE-OSV-1'] },
        { name: 'left-pad', version: '1.1.0', lockPath: 'b', advisoryIds: [] },
      ],
      [vuln],
    );
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.onlyOne).toEqual(['FIXTURE-OSV-1']);
    expect(result.findings[0]?.message).not.toContain('safe');
    expect(result.vulns).toEqual([vuln]);
  });

  it('emits nothing when the sets are equal', () => {
    process.env[FLAG] = '1';
    const result = duplicateAdvisories(
      [
        { name: 'left-pad', version: '1.0.0', lockPath: 'a', advisoryIds: [] },
        { name: 'left-pad', version: '1.1.0', lockPath: 'b', advisoryIds: [] },
      ],
      [],
    );
    expect(result.findings).toEqual([]);
    expect(result.events).toEqual([]);
  });

  it('emits only the event when the cache is missing', () => {
    process.env[FLAG] = '1';
    const result = duplicateAdvisories(
      [
        { name: 'left-pad', version: '1.0.0', lockPath: 'a', advisoryIds: null },
        { name: 'left-pad', version: '1.1.0', lockPath: 'b', advisoryIds: [] },
      ],
      [vuln],
    );
    expect(result.findings).toEqual([]);
    expect(result.events.map((event) => event.code)).toEqual(['271']);
    expect(result.vulns).toEqual([vuln]);
  });

  it('reports an id that exists only on the second copy and ignores a single copy', () => {
    process.env[FLAG] = '1';
    const result = duplicateAdvisories(
      [
        { name: 'left-pad', version: '1.0.0', lockPath: 'a', advisoryIds: ['FIXTURE-OSV-1'] },
        { name: 'left-pad', version: '1.1.0', lockPath: 'b', advisoryIds: ['FIXTURE-OSV-2'] },
        { name: 'ms', version: '2.0.0', lockPath: 'c', advisoryIds: ['FIXTURE-OSV-1'] },
      ],
      [],
    );
    expect(result.findings[0]?.onlyOne).toEqual(['FIXTURE-OSV-1', 'FIXTURE-OSV-2']);
    expect(result.findings.map((row) => row.name)).toEqual(['left-pad']);
    delete process.env[FLAG];
  });
});
