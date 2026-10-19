import { cp, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { runFix } from '../../../../src/fixer/index.js';
import { renderConsoleReport } from '../../../../src/reporters/console.js';

const fixture = join(import.meta.dirname, '../../../fixtures/unused-dep-app');

function keys(findings: { ruleId: string; file?: string; line?: number; severity: string }[]): string[] {
  return findings.map((f) => `${f.ruleId}\t${f.file ?? ''}\t${f.line ?? ''}\t${f.severity}`).sort();
}

describe('phase 48 unused direct dependencies', () => {
  it('counts unused directs and keeps imported and imported-not-called out', async () => {
    const result = await scan({ cwd: fixture, modules: ['deps'], offline: true });
    expect(result.metadata.unusedDirect?.packages).toEqual(['evil-unused', 'never-used']);
    expect(result.metadata.unusedDirect?.advisories).toBe(2);
    const idle = result.findings.find((f) => f.snippet?.startsWith('idle-lib@'));
    const used = result.findings.find((f) => f.snippet?.startsWith('used-lib@'));
    expect(idle?.reachability).toBe('imported-not-called');
    expect(used).toBeUndefined();
    const malicious = result.findings.find((f) => f.ruleId === 'DEPS-MALICIOUS-001');
    expect(malicious?.severity).toBe('critical');
    expect(malicious?.snippet).toContain('evil-unused');
    expect(renderConsoleReport(result)).toContain(
      '2 packages are never imported; removing them clears 2 advisories.',
    );
  });

  it('keeps the advisories in the scan while fix --unsafe removes only package.json names', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-unused-'));
    copies.push(dir);
    await cp(fixture, dir, { recursive: true });
    const before = await scan({ cwd: dir, modules: ['deps'], offline: true });
    const manifest = await readFile(join(dir, 'package.json'), 'utf8');
    const lock = await readFile(join(dir, 'package-lock.json'), 'utf8');
    const dry = await runFix({ cwd: dir, modules: ['deps'], unsafe: false });
    expect(dry.applied).toBe(false);
    const removal = dry.patches.find((p) => p.file === 'package.json' && p.safe === false);
    const removed = (removal?.diff ?? '').split('\n').filter((line) => line.startsWith('-') && !line.startsWith('---'));
    expect(removed.some((line) => line.includes('never-used'))).toBe(true);
    expect(removed.some((line) => line.includes('evil-unused'))).toBe(true);
    expect(removed.some((line) => line.includes('idle-lib') || line.includes('used-lib'))).toBe(false);
    expect(await readFile(join(dir, 'package.json'), 'utf8')).toBe(manifest);
    expect(keys(dry.findings.filter((f) => f.module === 'deps'))).toEqual(keys(before.findings));

    const applied = await runFix({
      cwd: dir,
      modules: ['deps'],
      unsafe: true,
      apply: true,
      force: true,
      noBranch: true,
    });
    expect(applied.notice).toBe('run npm install');
    const afterManifest = await readFile(join(dir, 'package.json'), 'utf8');
    expect(afterManifest).not.toContain('never-used');
    expect(afterManifest).not.toContain('evil-unused');
    expect(afterManifest).toContain('idle-lib');
    expect(afterManifest).toContain('used-lib');
    expect(await readFile(join(dir, 'package-lock.json'), 'utf8')).toBe(lock);
    expect(keys(applied.findings.filter((f) => f.module === 'deps'))).toEqual(keys(before.findings));
  });
});

const copies: string[] = [];

afterEach(async () => {
  await Promise.all(copies.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});
