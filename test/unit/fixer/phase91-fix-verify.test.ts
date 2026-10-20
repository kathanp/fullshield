import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';
import { scan } from '../../../src/core/engine.js';
import type { Finding } from '../../../src/core/finding.js';
import { explainFinding } from '../../../src/explain/index.js';
import { unifiedDiff } from '../../../src/fixer/diff.js';
import { runFix } from '../../../src/fixer/index.js';
import { withManifestOverride } from '../../../src/fixer/override.js';
import {
  allowPatchWrite,
  FIX_VERIFY_FLAG,
  writeIfAllowed,
} from '../../../src/fixer/verify.js';

const FLAG = FIX_VERIFY_FLAG;
const dirs: string[] = [];

const APP = "const express = require('express');\nconst app = express();\napp.use(express.json());\n";
const FIXED = "const express = require('express');\nconst app = express();\napp.use(express.json({ limit: '100kb' }));\n";
const WRONG = "// not a fix\nconst express = require('express');\nconst app = express();\napp.use(express.json());\n";
const EVAL_PATCH =
  "const express = require('express');\nconst app = express();\napp.use(express.json({ limit: '100kb' }));\neval(req.query.code);\n";

afterEach(async () => {
  delete process.env[FLAG];
  delete process.env.FULLSHIELD_EXPERIMENTAL_VEX;
  delete process.env.FULLSHIELD_EXPERIMENTAL_EXPLAIN;
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function project(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fullshield-p91-'));
  dirs.push(dir);
  await writeFile(join(dir, 'app.js'), APP);
  await writeFile(join(dir, 'caller.js'), "require('./app');\n");
  await writeFile(join(dir, 'other.js'), 'const unused = 1;\n');
  await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'p91', private: true }));
  return dir;
}

function bodyFinding(diff: string): Finding {
  return {
    id: 'bodylimitfinding1',
    ruleId: 'CONFIG-BODYLIMIT-001',
    module: 'config',
    title: 'express.json() has no size limit',
    severity: 'low',
    confidence: 'high',
    file: 'app.js',
    line: 3,
    message: 'app.use(express.json()) is registered without a size limit.',
    remediation: "Pass a limit, e.g. express.json({ limit: '100kb' }).",
    fix: { kind: 'code-patch', safe: true, diff },
  };
}

async function runCli(args: string[]): Promise<{ out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const program = createProgram({
    out: (text) => out.push(text),
    err: (text) => err.push(text),
  });
  const before = process.exitCode;
  process.exitCode = undefined;
  await program.parseAsync(['node', 'fullshield', ...args]);
  process.exitCode = before;
  return { out: out.join('\n'), err: err.join('\n') };
}

describe('Phase 91 fix verification', () => {
  it('leaves verified unset when the flag is off', async () => {
    const dir = await project();
    const result = await runFix({ cwd: dir, modules: ['config'] });
    expect(result.patches.some((patch) => patch.ruleId === 'CONFIG-BODYLIMIT-001')).toBe(true);
    expect(result.patches.every((patch) => patch.verified === undefined)).toBe(true);
    expect(result.warnings).toBeUndefined();
    expect(await readFile(join(dir, 'app.js'), 'utf8')).toBe(APP);
  });

  it('records removes-finding for a fix that clears the body-limit finding', async () => {
    const dir = await project();
    process.env[FLAG] = '1';
    const result = await runFix({ cwd: dir, modules: ['config'] });
    const body = result.patches.find((patch) => patch.ruleId === 'CONFIG-BODYLIMIT-001');
    expect(body?.verified).toBe('removes-finding');
    expect(await readFile(join(dir, 'app.js'), 'utf8')).toBe(APP);

    const written = await writeIfAllowed({
      cwd: dir,
      file: 'app.js',
      ruleId: 'CONFIG-BODYLIMIT-001',
      diff: unifiedDiff('app.js', APP, FIXED),
      base: APP,
      finding: bodyFinding(unifiedDiff('app.js', APP, FIXED)),
    });
    expect(written.status).toBe('removes-finding');
    expect(written.written).toBe(true);
    expect(await readFile(join(dir, 'app.js'), 'utf8')).toBe(FIXED);
  });

  it('records does-not-remove for a wrong patch and writes it only with --force-unverified', async () => {
    const dir = await project();
    const diff = unifiedDiff('app.js', APP, WRONG);
    const blocked = await writeIfAllowed({
      cwd: dir,
      file: 'app.js',
      ruleId: 'CONFIG-BODYLIMIT-001',
      diff,
      base: APP,
      finding: bodyFinding(diff),
    });
    expect(blocked.status).toBe('does-not-remove');
    expect(blocked.written).toBe(false);
    expect(blocked.warning).toContain('--force-unverified');
    expect(await readFile(join(dir, 'app.js'), 'utf8')).toBe(APP);

    const forced = await writeIfAllowed({
      cwd: dir,
      file: 'app.js',
      ruleId: 'CONFIG-BODYLIMIT-001',
      diff,
      base: APP,
      finding: bodyFinding(diff),
      forceUnverified: true,
    });
    expect(forced.status).toBe('does-not-remove');
    expect(forced.written).toBe(true);
    expect(await readFile(join(dir, 'app.js'), 'utf8')).toBe(WRONG);
  });

  it('does not write a patch that adds eval, even with --yes and --force-unverified', async () => {
    const dir = await project();
    const diff = unifiedDiff('app.js', APP, EVAL_PATCH);
    const result = await writeIfAllowed({
      cwd: dir,
      file: 'app.js',
      ruleId: 'CONFIG-BODYLIMIT-001',
      diff,
      base: APP,
      yes: true,
      forceUnverified: true,
      finding: bodyFinding(diff),
    });
    expect(result.status).toBe('introduces-finding');
    expect(result.written).toBe(false);
    expect(result.scanned).toContain('app.js');
    expect(result.scanned).toContain('caller.js');
    expect(result.scanned).not.toContain('other.js');
    expect(allowPatchWrite('introduces-finding', { enabled: true, yes: true, forceUnverified: true })).toBe(false);
    expect(await readFile(join(dir, 'app.js'), 'utf8')).toBe(APP);
  });

  it('verifies dependency overrides from the OSV cache only', async () => {
    const source = await readFile(new URL('../../../src/fixer/verify.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('child_process');
    expect(source).not.toContain('queryOsv');
    expect(source).not.toContain('api.osv.dev');
    expect(source).not.toContain('npm install');

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network'));
    try {
      const dir = await project();
      const cacheDir = join(dir, 'osv-cache');
      await mkdir(join(cacheDir, 'osv'), { recursive: true });
      const base = `${JSON.stringify({ name: 'p91', dependencies: { left: '1.0.0' } }, null, 2)}\n`;
      await writeFile(join(dir, 'package.json'), base);
      const cleared = withManifestOverride(base, 'npm', 'left', '1.0.1');
      const clearDiff = unifiedDiff('package.json', base, cleared);
      await writeFile(
        join(cacheDir, 'osv', 'left@1.0.1.json'),
        JSON.stringify({ fetchedAt: '2026-10-19T00:00:00.000Z', vulns: [] }),
      );
      const finding = depFinding(clearDiff, ['GHSA-old']);
      const ok = await writeIfAllowed({
        cwd: dir,
        file: 'package.json',
        ruleId: 'DEPS-VULN-001',
        diff: clearDiff,
        base,
        cacheDir,
        finding,
      });
      expect(ok.status).toBe('removes-finding');
      expect(ok.written).toBe(true);
      expect(await readFile(join(dir, 'package.json'), 'utf8')).toContain('"left": "1.0.1"');

      await writeFile(join(dir, 'package.json'), base);
      await writeFile(
        join(cacheDir, 'osv', 'left@1.0.1.json'),
        JSON.stringify({
          fetchedAt: '2026-10-19T00:00:00.000Z',
          vulns: [{ id: 'GHSA-old' }],
        }),
      );
      const still = await writeIfAllowed({
        cwd: dir,
        file: 'package.json',
        ruleId: 'DEPS-VULN-001',
        diff: clearDiff,
        base,
        cacheDir,
        finding,
      });
      expect(still.status).toBe('does-not-remove');
      expect(still.written).toBe(false);
      expect(await readFile(join(dir, 'package.json'), 'utf8')).toBe(base);

      const bumped = withManifestOverride(base, 'npm', 'left', '9.9.9');
      const badDiff = unifiedDiff('package.json', base, bumped);
      await writeFile(
        join(cacheDir, 'osv', 'left@9.9.9.json'),
        JSON.stringify({
          fetchedAt: '2026-10-19T00:00:00.000Z',
          vulns: [{ id: 'GHSA-new' }],
        }),
      );
      const introduced = await writeIfAllowed({
        cwd: dir,
        file: 'package.json',
        ruleId: 'DEPS-VULN-001',
        diff: badDiff,
        base,
        cacheDir,
        yes: true,
        forceUnverified: true,
        finding: depFinding(badDiff, ['GHSA-old']),
      });
      expect(introduced.status).toBe('introduces-finding');
      expect(introduced.written).toBe(false);
      expect(await readFile(join(dir, 'package.json'), 'utf8')).toBe(base);

      await rm(join(cacheDir, 'osv', 'left@1.0.1.json'));
      const missing = await writeIfAllowed({
        cwd: dir,
        file: 'package.json',
        ruleId: 'DEPS-VULN-001',
        diff: clearDiff,
        base,
        cacheDir,
        finding,
      });
      expect(missing.status).toBe('does-not-remove');
      expect(missing.written).toBe(false);

      const bumpDiff = '--- a/package.json\n+++ b/package.json\n# bump left from 1.0.0 to 2.0.0\n';
      await writeFile(
        join(cacheDir, 'osv', 'left@2.0.0.json'),
        JSON.stringify({ fetchedAt: '2026-10-19T00:00:00.000Z', vulns: [] }),
      );
      const bump = await writeIfAllowed({
        cwd: dir,
        file: 'package.json',
        ruleId: 'DEPS-VULN-001',
        diff: bumpDiff,
        base,
        cacheDir,
        finding: {
          ...depFinding(bumpDiff, ['GHSA-old']),
          fix: { kind: 'dependency-bump', safe: true, diff: bumpDiff },
        },
      });
      expect(bump.status).toBe('removes-finding');
      expect(await readFile(join(dir, 'package.json'), 'utf8')).toBe(base);
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it('verifies an explain suggestion with the same statuses', async () => {
    const dir = await project();
    const good = unifiedDiff('app.js', APP, FIXED);
    const finding = bodyFinding(good);
    process.env.FULLSHIELD_EXPERIMENTAL_EXPLAIN = '1';
    const off = await explainFinding({ cwd: dir, id: finding.id, findings: [finding] });
    expect(off).not.toContain('verified:');

    process.env[FLAG] = '1';
    const on = await explainFinding({ cwd: dir, id: finding.id, findings: [finding] });
    expect(on).toContain('verified: removes-finding');

    const wrong = bodyFinding(unifiedDiff('app.js', APP, WRONG));
    const missed = await explainFinding({ cwd: dir, id: wrong.id, findings: [wrong] });
    expect(missed).toContain('verified: does-not-remove');
  });

  it('keeps clean-app at zero findings while the flag is on', async () => {
    process.env[FLAG] = '1';
    const result = await scan({
      cwd: join(process.cwd(), 'test', 'fixtures', 'clean-app'),
      modules: ['sast', 'config', 'secrets'],
    });
    expect(result.findings).toEqual([]);
  });

  it('prints verified status from fix --experimental-fix-verify', async () => {
    const dir = await project();
    const cli = await runCli(['fix', dir, '--experimental-fix-verify', '--modules', 'config']);
    expect(cli.out).toContain('CONFIG-BODYLIMIT-001 app.js verified: removes-finding');
    expect(await readFile(join(dir, 'app.js'), 'utf8')).toBe(APP);
  });

  it('verifies the override fixture from its OSV cache without writing', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_VEX = '1';
    process.env[FLAG] = '1';
    const cwd = join(process.cwd(), 'test', 'fixtures', 'override-app');
    const before = await readFile(join(cwd, 'package.json'), 'utf8');
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network'));
    try {
      const result = await runFix({ cwd, modules: ['deps'], unsafe: true });
      const patch = result.patches.find((item) => item.diff.includes('leaf-vuln'));
      expect(patch?.verified).toBe('removes-finding');
      expect(await readFile(join(cwd, 'package.json'), 'utf8')).toBe(before);
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });
});

function depFinding(diff: string, references: string[]): Finding {
  return {
    id: 'depfinding000001',
    ruleId: 'DEPS-VULN-001',
    module: 'deps',
    title: 'Vulnerable dependency left@1.0.0',
    severity: 'high',
    confidence: 'high',
    file: 'package.json',
    snippet: 'left@1.0.0',
    message: 'left@1.0.0 is affected by GHSA-old.',
    remediation: 'Upgrade left to 1.0.1 or later (data from OSV).',
    references,
    fix: { kind: 'dependency-override', safe: false, diff },
  };
}
