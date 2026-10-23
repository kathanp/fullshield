import { afterEach, describe, expect, it } from 'vitest';

import { emitGitLab, enabled, FLAG, SIDECAR, validateGitLabSast, type GitLabFinding } from '../../../src/phases/p431.js';

afterEach(() => {
  delete process.env[FLAG];
});

const located: GitLabFinding = {
  id: '1',
  name: 'sqli',
  message: 'msg',
  description: 'desc',
  severity: 'High',
  file: 'src/a.js',
  line: 4,
  cwe: '89',
};

const floating: GitLabFinding = {
  id: '2',
  name: 'note',
  message: 'msg',
  description: 'desc',
  severity: 'Info',
};

describe('phase 431 GitLab report files', () => {
  it('writes no GitLab files when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(emitGitLab([located, floating])).toEqual({ written: false, sast: null, unmapped: null });
  });

  it('puts a located finding in the SAST report', () => {
    process.env[FLAG] = '1';
    const result = emitGitLab([located]);
    expect(result.written).toBe(true);
    expect(result.sast?.version).toBe('15.0.4');
    expect(result.sast?.header).toMatchObject({ sidecar: SIDECAR });
    const row = (result.sast?.vulnerabilities as Array<Record<string, unknown>>)[0];
    expect(row?.category).toBe('sast');
    expect(row?.location).toEqual({ file: 'src/a.js', start_line: 4 });
    expect(row?.identifiers).toEqual([{ type: 'cwe', name: 'CWE-89', value: '89' }]);
    expect(validateGitLabSast(result.sast)).toEqual([]);
    expect(result.unmapped).toEqual({ findings: [] });
  });

  it('sidecars a finding with no location and rejects a report without the header', () => {
    process.env[FLAG] = '1';
    const result = emitGitLab([floating]);
    expect(result.sast?.vulnerabilities).toEqual([]);
    expect(result.unmapped).toEqual({ findings: [floating] });
    expect(validateGitLabSast({ vulnerabilities: [] })).toContain('header must name unmapped.json');
  });

  it('rejects a non-object report and a vulnerability row that is not an object', () => {
    process.env[FLAG] = '1';
    const noCwe = emitGitLab([{ ...located, cwe: undefined, file: 'src/a.js', line: 4 }]);
    const row = (noCwe.sast?.vulnerabilities as Array<Record<string, unknown>>)[0];
    expect(row?.identifiers).toEqual([]);
    expect(emitGitLab([{ ...floating, file: 'src/a.js' }]).unmapped).toEqual({ findings: [{ ...floating, file: 'src/a.js' }] });
    expect(emitGitLab([{ ...floating, line: 3 }]).unmapped).toEqual({ findings: [{ ...floating, line: 3 }] });
    expect(validateGitLabSast(null)).toEqual(['GitLab report must be an object']);
    expect(validateGitLabSast([])).toEqual(['GitLab report must be an object']);
    expect(validateGitLabSast('x')).toEqual(['GitLab report must be an object']);
    const header = { header: { sidecar: SIDECAR }, vulnerabilities: 'nope' };
    expect(validateGitLabSast(header)).toContain('vulnerabilities must be an array');
    const partial = validateGitLabSast({
      header: { sidecar: SIDECAR },
      vulnerabilities: [null, { id: '1' }],
    });
    expect(partial).toContain('vulnerability must be an object');
    expect(partial).toContain('missing category');
    delete process.env[FLAG];
  });
});
