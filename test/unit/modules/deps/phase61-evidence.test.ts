import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

const app = join(import.meta.dirname, '../../../fixtures/upgrade-plan-app');

describe('phase 61 reachability evidence', () => {
  afterEach(() => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_REACH_EVIDENCE;
  });

  it('omits the field when the flag is off', async () => {
    const result = await scan({ cwd: app, modules: ['deps'], offline: true });
    expect(result.findings.every((finding) => finding.reachabilityEvidence === undefined)).toBe(true);
  });

  it('records import evidence and does not cite test files', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_REACH_EVIDENCE = '1';
    const result = await scan({ cwd: app, modules: ['deps'], offline: true });
    const express = result.findings.find((finding) => finding.snippet?.startsWith('express@'));
    expect(express?.reachabilityEvidence?.imports[0]).toMatchObject({ file: 'src/index.js', specifier: 'express' });
    expect(express?.reachabilityEvidence?.reason).toContain('src/index.js');
    const held = result.findings.find((finding) => finding.snippet?.startsWith('held@'));
    expect(held?.reachabilityEvidence?.imports).toEqual([]);
    expect(held?.reachabilityEvidence?.reason).toContain('No production file imports held');
    const blob = JSON.stringify(result.findings);
    expect(blob).not.toContain('test/');
    const off = keys(result);
    delete process.env.FULLSHIELD_EXPERIMENTAL_REACH_EVIDENCE;
    const plain = await scan({ cwd: app, modules: ['deps'], offline: true });
    expect(keys(plain)).toEqual(off);
  });
});

function keys(result: { findings: { ruleId: string; file?: string; line?: number; severity: string }[] }): string[] {
  return result.findings.map((f) => `${f.ruleId}\t${f.file ?? ''}\t${f.line ?? ''}\t${f.severity}`).sort();
}
