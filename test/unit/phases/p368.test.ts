import { describe, expect, it } from 'vitest';

import { enabled, FLAG, NOT_A_GRADE, sbomFieldReport } from '../../../src/phases/p368.js';

describe('phase 368 SBOM fields', () => {
  it('leaves the SBOM unchanged when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(sbomFieldReport([{ name: 'left-pad', version: '1.0.0', integrity: 'sha512-abc' }])).toBeNull();
  });

  it('has zero missing-hash rows when integrity is present', () => {
    process.env[FLAG] = '1';
    const report = sbomFieldReport([{ name: 'left-pad', version: '1.0.0', integrity: 'sha512-abc' }]);
    expect(report?.counts.hash).toBe(0);
    expect(report?.components[0]?.hash).toBe('sha512-abc');
    expect(report?.components[0]?.purl).toContain('pkg:npm/left-pad@1.0.0');
  });

  it('records a missing hash and still fills purl when integrity is absent', () => {
    process.env[FLAG] = '1';
    const report = sbomFieldReport([{ name: 'left-pad', version: '1.0.0' }]);
    expect(report?.counts.hash).toBe(1);
    expect(report?.components[0]?.purl).toBe('pkg:npm/left-pad@1.0.0');
    expect(report?.header).toBe(NOT_A_GRADE);
    expect(report?.header).toContain('not a grade');
    expect(report).not.toHaveProperty('score');
  });
});
