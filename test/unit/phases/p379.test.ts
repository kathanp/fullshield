import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { advisoriesFromOsvFile, enabled, FLAG } from '../../../src/phases/p379.js';
import { FsError } from '../../../src/phases/p378.js';

describe('phase 379 offline OSV file', () => {
  it('requires the flag', () => {
    expect(enabled()).toBe(false);
    expect(() => advisoriesFromOsvFile('advisories.json', '[]', [])).toThrow(FsError);
  });

  it('produces only the id written in the file', () => {
    process.env[FLAG] = '1';
    const text = JSON.stringify([
      {
        id: 'FIXTURE-OSV-1',
        affected: [{ package: { name: 'left-pad', ecosystem: 'npm' }, versions: ['1.0.0'] }],
      },
      {
        id: 'FIXTURE-OSV-2',
        affected: [{ package: { name: 'left-pad', ecosystem: 'npm' }, versions: ['9.9.9'] }],
      },
    ]);
    const report = advisoriesFromOsvFile('advisories.json', text, [{ name: 'left-pad', version: '1.0.0' }]);
    expect(report.advisorySource).toBe('file');
    expect(report.file).toBe('advisories.json');
    expect(report.current).toBe(false);
    expect(report.findings.map((row) => row.advisoryId)).toEqual(['FIXTURE-OSV-1']);
  });

  it('produces no vuln findings from an empty list', () => {
    process.env[FLAG] = '1';
    const report = advisoriesFromOsvFile('advisories.json', '{"results":[{"vulns":[]}]}', [{ name: 'left-pad', version: '1.0.0' }]);
    expect(report.findings).toEqual([]);
    const source = readFileSync(new URL('../../../src/phases/p379.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('node:http');
    expect(source).not.toContain('node:https');
    expect(source).not.toContain('node:net');
  });

  it('exits FS-E on a malformed file and yields no vuln rows', () => {
    process.env[FLAG] = '1';
    expect(() => advisoriesFromOsvFile('advisories.json', '{', [])).toThrow(FsError);
  });

  it('reads a vulns object, skips a package with no name, and rejects a malformed document', () => {
    process.env[FLAG] = '1';
    const wrapped = advisoriesFromOsvFile(
      'advisories.json',
      JSON.stringify({ vulns: [{ id: 'FIXTURE-OSV-3', affected: [{ package: { name: 'left-pad' }, versions: ['1.0.0'] }] }] }),
      [{ name: 'left-pad', version: '1.0.0' }],
    );
    expect(wrapped.findings.map((row) => row.advisoryId)).toEqual(['FIXTURE-OSV-3']);
    const skipped = advisoriesFromOsvFile(
      'advisories.json',
      JSON.stringify({
        results: [{ vulns: [{ id: 'FIXTURE-OSV-4', affected: [{ package: {} }, { versions: ['1.0.0'] }] }, { id: 'FIXTURE-OSV-5' }] }],
      }),
      [{ name: 'left-pad', version: '1.0.0' }],
    );
    expect(skipped.findings).toEqual([]);
    expect(() => advisoriesFromOsvFile('advisories.json', 'null', [])).toThrow(FsError);
    expect(() => advisoriesFromOsvFile('advisories.json', '{}', [])).toThrow(FsError);
    expect(() => advisoriesFromOsvFile('advisories.json', '{"results":[null]}', [])).toThrow(FsError);
    expect(() => advisoriesFromOsvFile('advisories.json', '{"results":[{"vulns":[{"id":""}]}]}', [])).toThrow(FsError);
    expect(() => advisoriesFromOsvFile('advisories.json', '{"vulns":[{"affected":[]}]}', [])).toThrow(FsError);
    delete process.env[FLAG];
  });
});
