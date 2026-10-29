import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { bumpPullRequestArgs } from '../../../src/modules/deps/bump-pr.js';
import { buildBumpPlan, bumpPlanText } from '../../../src/modules/deps/bump-extra.js';
import { registryCachePath } from '../../../src/provenance/index.js';

const dirs: string[] = [];

afterEach(async () => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_PROVENANCE;
  for (const dir of dirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

function finding(partial: Record<string, unknown>): Record<string, unknown> {
  return {
    ruleId: 'DEPS-VULN-001',
    reachability: 'reachable',
    severity: 'high',
    snippet: 'left-pad@1.0.0',
    references: ['GHSA-1'],
    fix: { kind: 'dependency-bump', diff: '# bump left-pad from 1.0.0 to 1.2.0\n' },
    ...partial,
  };
}

describe('phase 564 bump plan extras', () => {
  it('counts not-imported rows and groups one name and target into one pull request', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-group-'));
    dirs.push(cwd);
    const cache = await mkdtemp(join(tmpdir(), 'fullshield-group-cache-'));
    dirs.push(cache);
    const scan = JSON.stringify({
      findings: [
        finding({ severity: 'critical', references: ['GHSA-a'] }),
        finding({ severity: 'high', references: ['GHSA-b'] }),
        finding({
          severity: 'high',
          references: ['GHSA-c'],
          fix: { kind: 'dependency-bump', diff: '# bump left-pad from 1.0.0 to 1.3.0\n' },
        }),
      ],
    });
    const plan = await buildBumpPlan(scan, cwd, cache);
    expect(plan.bumps.map((row) => `${row.rank}:${row.to}:${row.clears}`)).toEqual(['1:1.2.0:2', '2:1.3.0:1']);
    const args = bumpPullRequestArgs(plan.bumps[0]!);
    expect(args.join('\n')).toContain('This upgrade clears 2 reachable findings.');
    expect(args.join('\n')).not.toMatch(/\bmerge\b|createComment|createReview/);
    expect(bumpPullRequestArgs({ ...plan.bumps[1]!, clears: 1 }).join('\n')).not.toContain('clears');
    const printed = await bumpPlanText(scan, cwd);
    expect(printed.endsWith('\n')).toBe(true);
    const parsed = JSON.parse(printed) as { skippedNotImported: number };
    expect(parsed.skippedNotImported).toBe(0);
  });

  it('reports install script text and does not execute it', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-scripts-'));
    dirs.push(cwd);
    const cache = await mkdtemp(join(tmpdir(), 'fullshield-scripts-cache-'));
    dirs.push(cache);
    await mkdir(join(cwd, 'node_modules', 'left-pad'), { recursive: true });
    await writeFile(
      join(cwd, 'node_modules', 'left-pad', 'package.json'),
      JSON.stringify({ scripts: { install: 'node evil.js', postinstall: 'echo hi' } }),
      'utf8',
    );
    const scan = JSON.stringify({
      findings: [
        finding({ reachability: 'not-imported', severity: 'critical' }),
        finding({}),
      ],
    });
    const plan = await buildBumpPlan(scan, cwd, cache);
    expect(plan.skippedNotImported).toBe(1);
    expect(plan.bumps).toHaveLength(1);
    expect(plan.installScripts).toEqual([
      {
        name: 'left-pad',
        scripts: [
          { hook: 'install', source: 'node evil.js' },
          { hook: 'postinstall', source: 'echo hi' },
        ],
      },
    ]);
    const source = await readFile(join(import.meta.dirname, '../../../src/modules/deps/bump-extra.ts'), 'utf8');
    expect(source).not.toContain('child_process');
    expect(source).not.toContain('execFile');
    const missing = JSON.stringify({
      findings: [finding({ snippet: 'gone@1.0.0', fix: { kind: 'dependency-bump', diff: '# bump gone from 1.0.0 to 1.2.0\n' } })],
    });
    expect((await buildBumpPlan(missing, cwd, cache)).installScripts).toEqual([{ name: 'gone', scripts: [] }]);
    await writeFile(join(cwd, 'node_modules', 'left-pad', 'package.json'), '{', 'utf8');
    expect((await buildBumpPlan(scan, cwd, cache)).installScripts[0]?.scripts).toEqual([]);
    await writeFile(join(cwd, 'node_modules', 'left-pad', 'package.json'), '[]', 'utf8');
    expect((await buildBumpPlan(scan, cwd, cache)).installScripts[0]?.scripts).toEqual([]);
    await writeFile(
      join(cwd, 'node_modules', 'left-pad', 'package.json'),
      JSON.stringify({ scripts: { preinstall: 'echo pre', install: 1 } }),
      'utf8',
    );
    expect((await buildBumpPlan(scan, cwd, cache)).installScripts[0]?.scripts).toEqual([
      { hook: 'preinstall', source: 'echo pre' },
    ]);
    await expect(bumpPlanText('{', cwd, cache)).rejects.toThrow(/cannot read bumps file/);
    await expect(bumpPlanText('null', cwd, cache)).rejects.toThrow(/cannot read bumps file/);
    await expect(bumpPlanText('[]', cwd, cache)).rejects.toThrow(/cannot read bumps file/);
    expect((await buildBumpPlan('{}', cwd, cache)).bumps).toEqual([]);
  });

  it('blocks a target that lacks attestations only when the provenance flag is on', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-prov-'));
    dirs.push(cwd);
    const cache = await mkdtemp(join(tmpdir(), 'fullshield-prov-cache-'));
    dirs.push(cache);
    const cacheFile = registryCachePath(cache, 'left-pad');
    await mkdir(join(cache, 'registry'), { recursive: true });
    await writeFile(
      cacheFile,
      JSON.stringify({ versions: { '1.2.0': { dist: {} }, '9.9.9': { dist: { attestations: { provenance: true } } } } }),
      'utf8',
    );
    const scan = JSON.stringify({ findings: [finding({})] });
    const off = await buildBumpPlan(scan, cwd, cache);
    expect(off.provenanceBlocked).toEqual([]);
    expect(off.bumps).toHaveLength(1);
    process.env.FULLSHIELD_EXPERIMENTAL_PROVENANCE = '1';
    const blocked = await buildBumpPlan(scan, cwd, cache);
    expect(blocked.bumps).toEqual([]);
    expect(blocked.provenanceBlocked).toEqual([{ name: 'left-pad', to: '1.2.0', reason: 'absent' }]);
    const present = JSON.stringify({
      findings: [finding({ fix: { kind: 'dependency-bump', diff: '# bump left-pad from 1.0.0 to 9.9.9\n' } })],
    });
    const allowed = await buildBumpPlan(present, cwd, cache);
    expect(allowed.provenanceBlocked).toEqual([]);
    expect(allowed.bumps.map((row) => row.to)).toEqual(['9.9.9']);
    await writeFile(cacheFile, '{', 'utf8');
    const broken = await buildBumpPlan(scan, cwd, cache);
    expect(broken.provenanceBlocked).toEqual([]);
    expect(broken.bumps).toHaveLength(1);
    const emptyCache = await mkdtemp(join(tmpdir(), 'fullshield-prov-empty-'));
    dirs.push(emptyCache);
    const missing = await buildBumpPlan(scan, cwd, emptyCache);
    expect(missing.provenanceBlocked).toEqual([]);
    expect(missing.bumps).toHaveLength(1);
    await writeFile(cacheFile, JSON.stringify({ versions: { '1.2.0': { dist: { attestations: null } } } }), 'utf8');
    expect((await buildBumpPlan(scan, cwd, cache)).provenanceBlocked).toEqual([
      { name: 'left-pad', to: '1.2.0', reason: 'absent' },
    ]);
    await writeFile(cacheFile, JSON.stringify({ versions: [] }), 'utf8');
    expect((await buildBumpPlan(scan, cwd, cache)).provenanceBlocked).toEqual([]);
    await writeFile(cacheFile, JSON.stringify({ versions: { '1.2.0': 'nope' } }), 'utf8');
    expect((await buildBumpPlan(scan, cwd, cache)).bumps).toHaveLength(1);
  });
});
