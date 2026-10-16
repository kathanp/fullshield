import { cpSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { runFix } from '../../../../src/fixer/index.js';
import { lockfileKind, withManifestOverride } from '../../../../src/fixer/override.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_VEX';
const fixture = join(process.cwd(), 'test', 'fixtures', 'override-app');
const dirs: string[] = [];

beforeEach(() => {
  delete process.env[FLAG];
});

afterEach(() => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function copyFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'fullshield-override-'));
  dirs.push(dir);
  cpSync(fixture, dir, { recursive: true });
  return dir;
}

describe('Phase 31 transitive dependency-override (experimental)', () => {
  it('does not attach dependency-override without the flag', async () => {
    const result = await scan({ cwd: fixture, modules: ['deps'], offline: true });
    const leaf = result.findings.filter(
      (f) => f.ruleId === 'DEPS-VULN-001' && (f.snippet ?? '').startsWith('leaf-vuln@'),
    );
    expect(leaf.length).toBeGreaterThan(0);
    expect(leaf.every((f) => f.fix?.kind !== 'dependency-override')).toBe(true);
  });

  it('proposes an unsafe npm overrides entry when the parent has no fixed release', async () => {
    process.env[FLAG] = '1';
    const result = await scan({ cwd: fixture, modules: ['deps'], offline: true });
    const leaf = result.findings.find(
      (f) => f.ruleId === 'DEPS-VULN-001' && (f.snippet ?? '').startsWith('leaf-vuln@1.0.0'),
    );
    expect(leaf?.fix?.kind).toBe('dependency-override');
    expect(leaf?.fix?.safe).toBe(false);
    expect(leaf?.fix?.diff).toMatch(/"overrides"/);
    expect(leaf?.fix?.diff).toMatch(/leaf-vuln/);
    expect(leaf?.fix?.diff).toMatch(/1\.0\.1/);
  });

  it('writes package.json overrides, leaves package-lock.json byte-identical, and says to run npm install', async () => {
    process.env[FLAG] = '1';
    const dir = copyFixture();
    const before = await scan({ cwd: dir, modules: ['deps'], offline: true });
    expect(
      before.findings.some(
        (f) => f.ruleId === 'DEPS-VULN-001' && (f.snippet ?? '').startsWith('leaf-vuln@1.0.0'),
      ),
    ).toBe(true);

    const fixed = await runFix({
      cwd: dir,
      modules: ['deps'],
      apply: true,
      unsafe: true,
      force: true,
      noBranch: true,
    });
    expect(fixed.applied).toBe(true);
    expect(fixed.patches.some((p) => p.safe === false && p.diff.includes('overrides'))).toBe(true);

    const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as {
      overrides?: Record<string, string>;
    };
    expect(manifest.overrides?.['leaf-vuln']).toBe('1.0.1');
    expect(fixed.notice).toBe('run npm install');

    const lockBefore = readFileSync(join(fixture, 'package-lock.json'));
    const lockAfter = readFileSync(join(dir, 'package-lock.json'));
    expect(Buffer.compare(lockBefore, lockAfter)).toBe(0);
  });

  it('writes pnpm.overrides / yarn resolutions for those lockfile kinds', () => {
    expect(lockfileKind('pnpm-lock.yaml')).toBe('pnpm');
    expect(lockfileKind('yarn.lock')).toBe('yarn');
    expect(lockfileKind('package-lock.json')).toBe('npm');

    const base = '{}\n';
    const pnpm = JSON.parse(withManifestOverride(base, 'pnpm', 'leaf-vuln', '1.0.1')) as {
      pnpm: { overrides: Record<string, string> };
    };
    expect(pnpm.pnpm.overrides['leaf-vuln']).toBe('1.0.1');

    const yarn = JSON.parse(withManifestOverride(base, 'yarn', 'leaf-vuln', '1.0.1')) as {
      resolutions: Record<string, string>;
    };
    expect(yarn.resolutions['leaf-vuln']).toBe('1.0.1');

    const npm = JSON.parse(withManifestOverride(base, 'npm', 'leaf-vuln', '1.0.1')) as {
      overrides: Record<string, string>;
    };
    expect(npm.overrides['leaf-vuln']).toBe('1.0.1');
  });
});
