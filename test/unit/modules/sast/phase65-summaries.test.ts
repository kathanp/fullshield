import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import type { Finding } from '../../../../src/core/finding.js';

const vulnerableApp = join(import.meta.dirname, '../../../fixtures/vulnerable-app');
const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const cacheDirs: string[] = [];

function stable(findings: readonly Finding[]): string {
  const rows = findings.map((finding) => ({
    ruleId: finding.ruleId,
    file: finding.file ?? '',
    line: finding.line ?? 0,
    severity: finding.severity,
    confidence: finding.confidence,
    message: finding.message,
    snippet: finding.snippet ?? '',
    trace: finding.trace ?? [],
  }));
  rows.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return JSON.stringify(rows);
}

async function useCache(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fullshield-taint-'));
  cacheDirs.push(dir);
  process.env.FULLSHIELD_TAINT_SUMMARY_DIR = dir;
  process.env.FULLSHIELD_TAINT_SUMMARIES = '1';
  return dir;
}

describe('phase 65 taint summaries', () => {
  afterEach(async () => {
    delete process.env.FULLSHIELD_TAINT_SUMMARIES;
    delete process.env.FULLSHIELD_TAINT_SUMMARY_DIR;
    await Promise.all(cacheDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('matches sorted findings with the flag off on vulnerable-app and clean-app', async () => {
    const vulnOff = await scan({ cwd: vulnerableApp, offline: true });
    const cleanOff = await scan({ cwd: cleanApp, offline: true });
    await useCache();
    const vulnOn = await scan({ cwd: vulnerableApp, offline: true });
    const vulnWarm = await scan({ cwd: vulnerableApp, offline: true });
    const cleanOn = await scan({ cwd: cleanApp, offline: true });
    expect(stable(vulnOn.findings)).toBe(stable(vulnOff.findings));
    expect(stable(vulnWarm.findings)).toBe(stable(vulnOff.findings));
    expect(stable(cleanOn.findings)).toBe(stable(cleanOff.findings));
  });

  it('discards a corrupt summary and drops the finding after the callee changes', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-summary-app-'));
    cacheDirs.push(dir);
    const cache = await useCache();
    execFileSync('cp', ['-R', join(vulnerableApp, 'src'), dir]);
    await writeFile(join(dir, 'package.json'), '{"name":"summary-app","version":"1.0.0"}\n');
    const dao = join(dir, 'src', 'data', 'alloc-dao.js');
    const before = await scan({ cwd: dir, modules: ['sast'] });
    expect(before.findings.some((finding) => finding.ruleId === 'SAST-SQLI-001' && finding.file === 'src/data/alloc-dao.js')).toBe(true);
    const files = await readdir(cache);
    expect(files.length).toBeGreaterThan(0);
    await Promise.all(files.map((file) => writeFile(join(cache, file), '{')));
    const rebuilt = await scan({ cwd: dir, modules: ['sast'] });
    expect(rebuilt.findings.some((finding) => finding.ruleId === 'SAST-SQLI-001' && finding.file === 'src/data/alloc-dao.js')).toBe(true);
    const original = await readFile(dao, 'utf8');
    await writeFile(dao, original.replace(" + threshold", ''));
    const after = await scan({ cwd: dir, modules: ['sast'] });
    expect(after.findings.some((finding) => finding.ruleId === 'SAST-SQLI-001' && finding.file === 'src/data/alloc-dao.js')).toBe(false);
  });

  it('matches sorted findings on checked-out bench apps', async () => {
    const home = process.env.FULLSHIELD_BENCH_DIR ?? join(homedir(), 'fullshield-bench');
    const names = ['NodeGoat', 'juice-shop', 'dvna', 'goof', 'vulnerable-node'];
    for (const name of names) {
      const cwd = join(home, name);
      if (!existsSync(join(cwd, 'package.json'))) continue;
      delete process.env.FULLSHIELD_TAINT_SUMMARIES;
      const off = await scan({ cwd, offline: true });
      await useCache();
      const on = await scan({ cwd, offline: true });
      expect(stable(on.findings)).toBe(stable(off.findings));
    }
  }, 600_000);
});
