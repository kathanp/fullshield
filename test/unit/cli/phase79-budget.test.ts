import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import pc from 'picocolors';

import { createProgram } from '../../../src/cli/program.js';
import {
  budgetArmed,
  budgetExpired,
  clearBudget,
  markTaintStopped,
  setBudgetClock,
} from '../../../src/core/budget.js';
import { DEFAULT_CONFIG } from '../../../src/core/config.js';
import { runScan, type ScanModule, type ScanOptions, type ScanResult } from '../../../src/core/engine.js';
import { makeFindingId, summarize, type Finding, type ModuleName } from '../../../src/core/finding.js';
import { sastModule } from '../../../src/modules/sast/engine.js';
import { renderConsoleReport } from '../../../src/reporters/console.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_BUDGET';

let roots: string[] = [];

function tempApp(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'fs-budget-'));
  roots.push(root);
  writeFileSync(join(root, 'package.json'), '{"name":"budget-fixture","version":"1.0.0"}\n');
  for (const [rel, text] of Object.entries(files)) {
    const abs = join(root, rel);
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, text);
  }
  return root;
}

function highFinding(file: string): Finding {
  return {
    id: makeFindingId('SAST-EVAL-001', file, 'budget-high'),
    ruleId: 'SAST-EVAL-001',
    module: 'sast',
    title: 'Budget fixture high',
    severity: 'high',
    confidence: 'high',
    file,
    line: 1,
    snippet: 'budget-high',
    message: 'high finding in the scanned part',
    remediation: 'remove it',
  };
}

function sourceFiles(files: readonly string[]): string[] {
  return files.filter((file) => /\.[cm]?[jt]sx?$/.test(file));
}

/** Slow per file only while the budget is armed, so a flag-off scan stays fast. */
function slowSast(highInFirst: boolean): ScanModule {
  return {
    name: 'sast',
    async run(ctx) {
      const files = sourceFiles(ctx.files);
      const findings: Finding[] = [];
      for (let index = 0; index < files.length; index += 1) {
        const file = files[index];
        if (file === undefined) continue;
        if (budgetExpired()) {
          markTaintStopped('sast', files.length - index);
          break;
        }
        if (highInFirst && index === 0) findings.push(highFinding(file));
        if (budgetArmed()) await new Promise((resolve) => setTimeout(resolve, 1200));
      }
      return findings;
    },
  };
}

function tracker(name: ModuleName, calls: string[]): ScanModule {
  return {
    name,
    run: () => {
      calls.push(name);
      return Promise.resolve([]);
    },
  };
}

async function runCli(
  args: string[],
  scan?: (options: ScanOptions) => Promise<ScanResult>,
): Promise<{ out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  process.exitCode = undefined;
  const program = createProgram({
    out: (text) => out.push(text),
    err: (text) => err.push(text),
    scan,
  });
  await program.parseAsync(['node', 'fullshield', ...args]);
  return { out: out.join('\n'), err: err.join('\n') };
}

function stableMetadata(metadata: ScanResult['metadata']): Record<string, unknown> {
  const copy = { ...metadata } as Record<string, unknown>;
  delete copy.durationMs;
  delete copy.startedAt;
  return copy;
}

beforeEach(() => {
  setBudgetClock(undefined);
  process.exitCode = undefined;
});

afterEach(() => {
  setBudgetClock(undefined);
  clearBudget();
  delete process.env[FLAG];
  for (const root of roots) rmSync(root, { recursive: true, force: true });
  roots = [];
});

describe('Phase 79 time budget', () => {
  it('documents exit 3 as an incomplete scan, not a clean one', () => {
    const text = readFileSync(join(process.cwd(), 'docs', 'errors.md'), 'utf8');
    expect(text).toContain('FULLSHIELD_EXPERIMENTAL_BUDGET');
    expect(text).toContain('FS-E012');
    expect(text).toMatch(/exit code 3/i);
    expect(text).toMatch(/not a clean scan/i);
  });

  it('slow fake rule and --max-time 1 exits 3 with incomplete when nothing meets --fail-on', async () => {
    const root = tempApp({
      'src/a.js': 'const a = 1;\n',
      'src/b.js': 'const b = 1;\n',
      'src/c.js': 'const c = 1;\n',
    });
    const calls: string[] = [];
    const scan = (options: ScanOptions) =>
      runScan(options, [slowSast(false), tracker('deps', calls), tracker('secrets', calls), tracker('config', calls)]);
    const { out, err } = await runCli(
      ['scan', root, '--max-time', '1', '--fail-on', 'high', '--json', '--experimental-budget', '--modules', 'sast,deps,secrets,config'],
      scan,
    );
    expect(err).toBe('');
    const parsed = JSON.parse(out) as {
      findings: unknown[];
      metadata: { incomplete?: boolean; incompleteModules?: string[]; filesNotTaintChecked?: number };
    };
    expect(parsed.findings).toEqual([]);
    expect(parsed.metadata.incomplete).toBe(true);
    expect(parsed.metadata.incompleteModules).toEqual(['sast']);
    expect(parsed.metadata.filesNotTaintChecked).toBeGreaterThan(0);
    expect(calls).toEqual(['deps', 'secrets', 'config']);
    expect(process.exitCode).toBe(3);
  });

  it('exits 1 when a high finding is in the part that was scanned', async () => {
    const root = tempApp({
      'src/a.js': 'const a = 1;\n',
      'src/b.js': 'const b = 1;\n',
      'src/c.js': 'const c = 1;\n',
    });
    const scan = (options: ScanOptions) =>
      runScan(options, [slowSast(true), tracker('deps', []), tracker('secrets', []), tracker('config', [])]);
    const { out } = await runCli(
      ['scan', root, '--max-time', '1', '--fail-on', 'high', '--json', '--experimental-budget', '--modules', 'sast,deps,secrets,config'],
      scan,
    );
    const parsed = JSON.parse(out) as {
      findings: Array<{ severity: string }>;
      metadata: { incomplete?: boolean };
    };
    expect(parsed.metadata.incomplete).toBe(true);
    expect(parsed.findings.some((finding) => finding.severity === 'high')).toBe(true);
    expect(process.exitCode).toBe(1);
  });

  it('does not report an incomplete scan with zero findings as clean', () => {
    const result: ScanResult = {
      findings: [],
      summary: summarize([]),
      metadata: {
        version: '0.0.0',
        startedAt: '2026-10-19T00:00:00.000Z',
        durationMs: 1,
        cwd: '/tmp/budget',
        filesScanned: 3,
        modulesRequested: ['sast'],
        modulesRun: ['sast'],
        incomplete: true,
        incompleteModules: ['sast'],
        filesNotTaintChecked: 2,
      },
      config: DEFAULT_CONFIG,
    };
    const text = renderConsoleReport(result);
    const line = 'Scan stopped at budget. 2 files not taint-checked.';
    expect(text).toContain(pc.yellow(line));
    expect(text.split('Scan stopped at budget.').length - 1).toBe(1);
    expect(text).not.toContain('No findings');
  });

  it('flag off: --max-time leaves output and exit codes unchanged', async () => {
    const root = tempApp({
      'src/a.js': 'const a = 1;\n',
      'src/b.js': 'const b = 1;\n',
      'src/c.js': 'const c = 1;\n',
    });
    const scan = (options: ScanOptions) => runScan(options, [slowSast(true)]);
    const plain = await runCli(['scan', root, '--json', '--fail-on', 'high', '--modules', 'sast'], scan);
    const plainExit = process.exitCode ?? 0;
    const timed = await runCli(
      ['scan', root, '--json', '--fail-on', 'high', '--modules', 'sast', '--max-time', '1'],
      scan,
    );
    const plainJson = JSON.parse(plain.out) as ScanResult;
    const timedJson = JSON.parse(timed.out) as ScanResult;
    expect(timed.err).toBe(plain.err);
    expect(plainExit).toBe(1);
    expect(process.exitCode).toBe(plainExit);
    expect(timedJson.findings).toEqual(plainJson.findings);
    expect(timedJson.summary).toEqual(plainJson.summary);
    expect(stableMetadata(timedJson.metadata)).toEqual(stableMetadata(plainJson.metadata));
    expect(timedJson.metadata.incomplete).toBeUndefined();
    expect(plainJson.findings.some((finding) => finding.severity === 'high')).toBe(true);

    delete process.env[FLAG];
    process.exitCode = undefined;
    const real = tempApp({ 'src/a.js': 'const a = 1;\n' });
    const realPlain = await runCli(['scan', real, '--json', '--fail-on', 'high', '--modules', 'sast']);
    process.exitCode = undefined;
    const realTimed = await runCli(['scan', real, '--json', '--fail-on', 'high', '--modules', 'sast', '--max-time', 'nope']);
    expect(realTimed.err).toBe(realPlain.err);
    expect(process.exitCode ?? 0).toBe(0);
    const realPlainJson = JSON.parse(realPlain.out) as ScanResult;
    const realTimedJson = JSON.parse(realTimed.out) as ScanResult;
    expect(realTimedJson.findings).toEqual(realPlainJson.findings);
    expect(stableMetadata(realTimedJson.metadata)).toEqual(stableMetadata(realPlainJson.metadata));
    expect(realTimedJson.metadata.incomplete).toBeUndefined();
  });

  it('stops real SAST taint when the budget is already spent and still finishes other modules', async () => {
    const root = tempApp({
      'src/a.js': 'const a = 1;\n',
      'src/b.js': 'const b = 1;\n',
    });
    let reads = 0;
    setBudgetClock(() => {
      reads += 1;
      return reads === 1 ? 0 : 1_000_000;
    });
    process.env[FLAG] = '1';
    for (const streamAt of [undefined, '1'] as const) {
      if (streamAt === '1') process.env.FULLSHIELD_SAST_STREAM_AT = '1';
      else delete process.env.FULLSHIELD_SAST_STREAM_AT;
      reads = 0;
      const calls: string[] = [];
      const result = await runScan(
        { cwd: root, modules: ['deps', 'sast', 'secrets', 'config'], maxTimeSeconds: 1 },
        [tracker('deps', calls), sastModule, tracker('secrets', calls), tracker('config', calls)],
      );
      expect(result.metadata.incomplete).toBe(true);
      expect(result.metadata.incompleteModules).toEqual(['sast']);
      expect(result.metadata.filesNotTaintChecked).toBe(2);
      expect(calls).toEqual(['deps', 'secrets', 'config']);
      expect(result.findings.filter((finding) => finding.module === 'sast')).toEqual([]);
    }
  });

  it('skips taint expansion after the current file when the budget expires mid-scan', async () => {
    const root = tempApp({
      'src/a.js': 'const a = 1;\n',
      'src/b.js': 'const b = 1;\n',
    });
    let reads = 0;
    setBudgetClock(() => {
      reads += 1;
      return reads >= 4 ? 1_000_000 : 0;
    });
    process.env[FLAG] = '1';
    for (const streamAt of [undefined, '1'] as const) {
      if (streamAt === '1') process.env.FULLSHIELD_SAST_STREAM_AT = '1';
      else delete process.env.FULLSHIELD_SAST_STREAM_AT;
      reads = 0;
      const result = await runScan({ cwd: root, modules: ['sast'], maxTimeSeconds: 1 }, [sastModule]);
      expect(result.metadata.incomplete).toBe(true);
      expect(result.metadata.incompleteModules).toEqual(['sast']);
      expect(result.metadata.filesNotTaintChecked).toBe(1);
    }
  });

  it('marks SAST incomplete when the budget expires before taint expansion on the last file', async () => {
    const root = tempApp({ 'src/a.js': 'const a = 1;\n' });
    let reads = 0;
    setBudgetClock(() => {
      reads += 1;
      return reads >= 4 ? 1_000_000 : 0;
    });
    process.env[FLAG] = '1';
    for (const streamAt of [undefined, '1'] as const) {
      if (streamAt === '1') process.env.FULLSHIELD_SAST_STREAM_AT = '1';
      else delete process.env.FULLSHIELD_SAST_STREAM_AT;
      reads = 0;
      const result = await runScan({ cwd: root, modules: ['sast'], maxTimeSeconds: 1 }, [sastModule]);
      expect(result.metadata.incomplete).toBe(true);
      expect(result.metadata.filesNotTaintChecked).toBe(0);
    }
  });

  it('rejects a non-positive --max-time only when the budget flag is on', async () => {
    const root = tempApp({ 'src/a.js': 'const a = 1;\n' });
    const bad = await runCli(['scan', root, '--max-time', '0', '--experimental-budget', '--modules', 'sast']);
    expect(bad.err).toContain('FS-E012');
    expect(bad.err).toContain('invalid --max-time');
    expect(process.exitCode).toBe(2);

    delete process.env[FLAG];
    process.exitCode = undefined;
    const ignored = await runCli(['scan', root, '--max-time', '0', '--modules', 'sast', '--json']);
    expect(ignored.err).toBe('');
    expect(process.exitCode ?? 0).toBe(0);
    const parsed = JSON.parse(ignored.out) as ScanResult;
    expect(parsed.metadata.incomplete).toBeUndefined();
  });

  it('does not arm a budget that the scan finishes inside', async () => {
    const root = tempApp({ 'src/a.js': 'const a = 1;\n' });
    setBudgetClock(() => 0);
    process.env[FLAG] = '1';
    const open = await runScan({ cwd: root, modules: ['sast'] }, [sastModule]);
    const bounded = await runScan({ cwd: root, modules: ['sast'], maxTimeSeconds: 60 }, [sastModule]);
    expect(bounded.metadata.incomplete).toBeUndefined();
    expect(bounded.findings).toEqual(open.findings);
  });
});
