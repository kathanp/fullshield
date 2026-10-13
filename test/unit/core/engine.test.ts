import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  IMPLEMENTED_MODULES,
  builtinModules,
  runScan,
  scan,
  type ScanModule,
} from '../../../src/core/engine.js';
import { makeFindingId, type Finding, type ModuleName } from '../../../src/core/finding.js';
import { packageVersion } from '../../../src/core/version.js';

const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');

function mkFinding(ruleId: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id: makeFindingId(ruleId, overrides.file, overrides.snippet),
    ruleId,
    module: 'sast',
    title: `title for ${ruleId}`,
    severity: 'medium',
    confidence: 'high',
    message: 'msg',
    remediation: 'fix',
    ...overrides,
  };
}

function fakeModule(name: ModuleName, findings: Finding[]): ScanModule {
  return { name, run: () => Promise.resolve(findings) };
}

// NOTE (phase 2): these assertions were originally phase-1 snapshots
// (registry === []). They are rewritten as phase-proof invariants that only
// get stronger as modules land; the clean-app zero-findings expectation is
// unchanged and permanent.
describe('module registry', () => {
  it('keeps IMPLEMENTED_MODULES consistent with the built-in registry', () => {
    expect(IMPLEMENTED_MODULES).toEqual(builtinModules.map((m) => m.name));
    const names = builtinModules.map((m) => m.name);
    expect(new Set(names).size).toBe(names.length);
  });
});

describe('runScan', () => {
  it('scans clean-app with built-in modules and returns no findings (permanent invariant)', async () => {
    const result = await scan({ cwd: cleanApp });
    expect(result.findings).toEqual([]);
    expect(result.summary.total).toBe(0);
    expect(result.metadata.filesScanned).toBeGreaterThanOrEqual(3);
    expect(result.metadata.modulesRequested).toEqual(['deps', 'secrets', 'sast', 'config']);
    expect(result.metadata.modulesRun).toEqual(
      result.metadata.modulesRequested.filter((m) => IMPLEMENTED_MODULES.includes(m)),
    );
    expect(result.metadata.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('reports the real package version in metadata', async () => {
    const result = await scan({ cwd: cleanApp });
    const pkg = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8')) as {
      version: string;
    };
    expect(result.metadata.version).toBe(pkg.version);
    expect(packageVersion()).toBe(pkg.version);
  });

  it('throws on a path that is not a directory', async () => {
    await expect(scan({ cwd: join(cleanApp, 'does-not-exist') })).rejects.toThrow(
      /not a directory/,
    );
  });

  it('runs only requested modules that are implemented', async () => {
    const sast = fakeModule('sast', [mkFinding('SAST-TEST-001', { file: 'a.ts' })]);
    const secrets = fakeModule('secrets', [mkFinding('SECRET-TEST-001', { file: 'b.ts' })]);
    const result = await runScan({ cwd: cleanApp, modules: ['sast', 'deps'] }, [sast, secrets]);
    expect(result.metadata.modulesRequested).toEqual(['sast', 'deps']);
    expect(result.metadata.modulesRun).toEqual(['sast']);
    expect(result.findings.map((f) => f.ruleId)).toEqual(['SAST-TEST-001']);
  });

  it('merges, dedupes by id, and sorts findings by severity', async () => {
    const duplicate = mkFinding('SAST-DUP-001', { file: 'dup.ts', severity: 'low' });
    const sast = fakeModule('sast', [
      mkFinding('SAST-A-001', { file: 'a.ts', severity: 'high' }),
      duplicate,
    ]);
    const secrets = fakeModule('secrets', [
      { ...duplicate },
      mkFinding('SECRET-B-001', { file: 'b.ts', severity: 'critical', module: 'secrets' }),
    ]);
    const result = await runScan({ cwd: cleanApp, modules: ['sast', 'secrets'] }, [sast, secrets]);
    expect(result.findings.map((f) => f.ruleId)).toEqual([
      'SECRET-B-001',
      'SAST-A-001',
      'SAST-DUP-001',
    ]);
    expect(result.summary.total).toBe(3);
    expect(result.summary.bySeverity.critical).toBe(1);
    expect(result.summary.bySeverity.high).toBe(1);
    expect(result.summary.bySeverity.low).toBe(1);
  });

  it('passes walked files and config to modules', async () => {
    let seenFiles: string[] = [];
    const probe: ScanModule = {
      name: 'config',
      run: (ctx) => {
        seenFiles = ctx.files;
        expect(ctx.cwd).toBe(cleanApp);
        expect(ctx.config.failOn).toBe('high');
        return Promise.resolve([]);
      },
    };
    await runScan({ cwd: cleanApp, modules: ['config'] }, [probe]);
    expect(seenFiles).toContain('src/index.js');
    expect(seenFiles).toContain('package.json');
  });
});
