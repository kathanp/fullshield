import { cpSync, mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import {
  analyzePackageDir,
  analyzeWorkflowTampering,
  analyzeWormIndicators,
  provenanceCoverage,
} from '../../../src/supply/index.js';
import { experimentalVex } from '../../../src/supply/experimental.js';

const fixtures = join(dirname(fileURLToPath(import.meta.url)), '../../fixtures/supply');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_VEX';
const NEW_IDS = ['SUPPLY-WORM-001', 'SUPPLY-WORKFLOW-001'];

const dirs: string[] = [];

beforeEach(() => {
  delete process.env[FLAG];
});

afterEach(() => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('Phase 31 worm / workflow indicators (experimental)', () => {
  it('does not emit new supply IDs when FULLSHIELD_EXPERIMENTAL_VEX is unset', () => {
    expect(experimentalVex()).toBe(false);
    const worm = analyzePackageDir(join(fixtures, 'worm-pkg'));
    const tamper = analyzePackageDir(join(fixtures, 'workflow-tamper-pkg'));
    expect(worm.some((f) => NEW_IDS.includes(f.ruleId))).toBe(false);
    expect(tamper.some((f) => NEW_IDS.includes(f.ruleId))).toBe(false);
  });

  it('flags a seeded worm that reads npm tokens and publishes', () => {
    process.env[FLAG] = '1';
    const findings = analyzeWormIndicators(join(fixtures, 'worm-pkg'));
    const hit = findings.find((f) => f.ruleId === 'SUPPLY-WORM-001');
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe('critical');
  });

  it('flags GitHub token + GitHub API repo/workflow creation as a worm', () => {
    process.env[FLAG] = '1';
    const findings = analyzeWormIndicators(join(fixtures, 'worm-github-pkg'));
    expect(findings.some((f) => f.ruleId === 'SUPPLY-WORM-001' && f.severity === 'critical')).toBe(
      true,
    );
  });

  it('flags NPM_TOKEN + registry PUT as a worm', () => {
    process.env[FLAG] = '1';
    const findings = analyzeWormIndicators(join(fixtures, 'worm-registry-pkg'));
    expect(findings.some((f) => f.ruleId === 'SUPPLY-WORM-001')).toBe(true);
  });

  it('does not flag credential reads without publish/registry/GitHub/workflow writes', () => {
    process.env[FLAG] = '1';
    const findings = analyzeWormIndicators(join(fixtures, 'worm-negative-pkg'));
    expect(findings.filter((f) => f.ruleId === 'SUPPLY-WORM-001')).toEqual([]);
    expect(analyzeWorkflowTampering(join(fixtures, 'worm-negative-pkg'))).toEqual([]);
  });

  it('flags install scripts or code that write CI / git hooks / .github', () => {
    process.env[FLAG] = '1';
    const findings = analyzeWorkflowTampering(join(fixtures, 'workflow-tamper-pkg'));
    expect(findings.some((f) => f.ruleId === 'SUPPLY-WORKFLOW-001')).toBe(true);
  });

  it('scan of a seeded worm package is silent without the flag and critical with it', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-worm-scan-'));
    dirs.push(dir);
    writeFileSync(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'worm-app', version: '1.0.0', dependencies: { 'worm-pkg': '1.0.0' } }),
    );
    writeFileSync(
      join(dir, 'package-lock.json'),
      JSON.stringify({
        name: 'worm-app',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { 'worm-pkg': '1.0.0' } },
          'node_modules/worm-pkg': { version: '1.0.0' },
        },
      }),
    );
    writeFileSync(
      join(dir, 'fullshield.config.json'),
      JSON.stringify({ deps: { offline: true, cacheDir: 'osv-cache' } }),
    );
    mkdirSync(join(dir, 'osv-cache', 'osv'), { recursive: true });
    mkdirSync(join(dir, 'node_modules', 'worm-pkg'), { recursive: true });
    cpSync(join(fixtures, 'worm-pkg'), join(dir, 'node_modules', 'worm-pkg'), { recursive: true });

    const off = await scan({ cwd: dir, modules: ['deps'], offline: true });
    expect(off.findings.some((f) => NEW_IDS.includes(f.ruleId))).toBe(false);

    process.env[FLAG] = '1';
    const on = await scan({ cwd: dir, modules: ['deps'], offline: true });
    expect(on.findings.some((f) => f.ruleId === 'SUPPLY-WORM-001' && f.severity === 'critical')).toBe(
      true,
    );
  });
});

describe('Phase 31 provenance coverage score', () => {
  it('reports the percent of deps with provenance and does not guess', () => {
    const score = provenanceCoverage(
      [
        { name: 'a', version: '1.0.0' },
        { name: 'b', version: '1.0.0' },
        { name: 'c', version: '1.0.0' },
      ],
      new Map([
        ['a@1.0.0', true],
        ['b@1.0.0', false],
      ]),
    );
    expect(score.total).toBe(3);
    expect(score.withProvenance).toBe(1);
    expect(score.percent).toBeCloseTo(100 / 3);
    expect(score.unknown).toBe(1);
  });

  it('is 0 when no packages are listed', () => {
    expect(provenanceCoverage([], new Map()).percent).toBe(0);
  });
});
