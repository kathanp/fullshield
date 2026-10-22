import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import { drill, isProductionCache, main, productionCache } from '../../../src/phases/p497.js';

const root = process.cwd();
const script = join(root, 'scripts', 'phase497-drill.mjs');
const ADVISORY = 'GHSA-p497-drill-local';
const PKG = 'p497drillpkg';

function runScript(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_DRILL = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_DRILL;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

function fixture(options: { extraAdvisory?: string; dependencies?: Record<string, string>; lock?: boolean; advisory?: boolean } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'fs497-'));
  const deps = options.dependencies ?? { [PKG]: '1.0.0' };
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'p497-app', version: '1.0.0', dependencies: deps }));
  writeFileSync(
    join(dir, 'fullshield.config.json'),
    JSON.stringify({ deps: { cacheDir: 'osv-cache', offline: true } }),
  );
  mkdirSync(join(dir, 'osv-cache', 'osv'), { recursive: true });
  if (options.lock !== false) {
    writeFileSync(
      join(dir, 'package-lock.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: { [`node_modules/${PKG}`]: { version: '1.0.0' } },
      }),
    );
  }
  if (options.advisory !== false) {
    writeFileSync(
      join(dir, 'osv-cache', 'osv', `${PKG}@1.0.0.json`),
      JSON.stringify({
        fetchedAt: '2026-10-22T00:00:00.000Z',
        vulns: [{ id: ADVISORY, summary: 'local drill fixture' }],
      }),
    );
  }
  if (options.extraAdvisory !== undefined) {
    writeFileSync(
      join(dir, 'osv-cache', 'osv', 'orphan.json'),
      JSON.stringify({ vulns: [{ id: options.extraAdvisory }] }),
    );
  }
  return dir;
}

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  const stdoutWrite = process.stdout.write.bind(process.stdout);
  const stderrWrite = process.stderr.write.bind(process.stderr);
  process.stdout.write = (chunk: unknown) => {
    out.push(String(chunk));
    return true;
  };
  process.stderr.write = (chunk: unknown) => {
    err.push(String(chunk));
    return true;
  };
  return {
    text: () => ({ stdout: out.join(''), stderr: err.join('') }),
    restore() {
      process.stdout.write = stdoutWrite;
      process.stderr.write = stderrWrite;
    },
  };
}

describe('phase 497 offline drill', () => {
  it('treats the home cache as production and a sibling directory as not', () => {
    const prod = productionCache();
    expect(prod).toBe(join(homedir(), '.cache', 'fullshield'));
    expect(isProductionCache(prod)).toBe(true);
    expect(isProductionCache(join(prod, 'osv'))).toBe(true);
    expect(isProductionCache(join(homedir(), '.cache', 'fullshield-other'))).toBe(false);
    expect(isProductionCache(join(tmpdir(), 'fs497-not-cache'))).toBe(false);
  });

  it('rejects a production cache path before scanning', async () => {
    const log = join(mkdtempSync(join(tmpdir(), 'fs497-log-')), 'drill.log');
    const result = await drill(productionCache(), 20_000, undefined, log);
    expect(result.code).toBe(1);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('production cache path is rejected\n');
    expect(() => readFileSync(log)).toThrow();
  });

  it('records an unreviewed drill when the local advisory and package are in the scan', async () => {
    const dir = fixture();
    const log = join(dir, 'drill.log');
    const result = await drill(dir, 20_000, undefined, log);
    expect(result.code).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).toBe(`drill ok ${PKG}\n`);
    expect(readFileSync(log, 'utf8')).toBe('drill unreviewed\n');
    expect(isProductionCache(dir)).toBe(false);
  }, 30_000);

  it('fails a missing advisory id, a package name absent from findings, a broken SARIF file, and a spent budget', async () => {
    const missingId = fixture({ extraAdvisory: 'GHSA-p497-not-in-scan' });
    const idResult = await drill(missingId, 20_000, undefined, join(missingId, 'drill.log'));
    expect(idResult.code).toBe(1);
    expect(idResult.stderr).toBe('advisory id missing from JSON\n');

    const missingName = fixture({
      dependencies: { [PKG]: '1.0.0', zzzzdrillabsentpkg: '1.0.0' },
    });
    const nameResult = await drill(missingName, 20_000, undefined, join(missingName, 'drill.log'));
    expect(nameResult.code).toBe(1);
    expect(nameResult.stderr).toBe('package name missing from findings\n');

    const sarifDir = fixture();
    const sarif = join(sarifDir, 'bad.sarif.json');
    writeFileSync(sarif, JSON.stringify({ version: '0' }));
    const sarifResult = await drill(sarifDir, 20_000, sarif, join(sarifDir, 'drill.log'));
    expect(sarifResult.code).toBe(1);
    expect(sarifResult.stderr).toContain('version must be "2.1.0"');

    const slow = fixture();
    const budget = await drill(slow, -1, undefined, join(slow, 'drill.log'));
    expect(budget.code).toBe(1);
    expect(budget.stderr).toBe('time budget exceeded\n');
  }, 30_000);

  it('prints usage and rejects a production cache token on the command line', async () => {
    const usage = capture();
    try {
      expect(await main(['--project'])).toBe(2);
      expect(usage.text().stderr).toBe('usage: --project <dir> --log <file>\n');
    } finally {
      usage.restore();
    }

    const blocked = capture();
    try {
      expect(await main([productionCache(), '--project', productionCache(), '--log', 'drill.log'])).toBe(1);
      expect(blocked.text().stderr).toBe('production cache path is rejected\n');
      expect(blocked.text().stdout).toBe('');
    } finally {
      blocked.restore();
    }
  });

  it('writes the drill line from main for a temporary project', async () => {
    const dir = fixture();
    const log = join(dir, 'drill.log');
    const io = capture();
    try {
      expect(await main(['--project', dir, '--log', log, '--budget-ms', '20000'])).toBe(0);
      expect(io.text().stdout).toBe(`drill ok ${PKG}\n`);
      expect(io.text().stderr).toBe('');
    } finally {
      io.restore();
    }
    expect(readFileSync(log, 'utf8')).toBe('drill unreviewed\n');
  }, 30_000);

  it('does nothing when the flag is off', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs497-off-'));
    const result = runScript(['--project', dir, '--log', join(dir, 'drill.log')], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });
});
