import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { parseLockfileGraph } from '../../../../src/modules/deps/lockfile.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const dirs: string[] = [];

async function tree(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fs-lock-'));
  dirs.push(dir);
  await writeFile(
    join(dir, 'package.json'),
    JSON.stringify({ name: 'broken-lock', version: '1.0.0', scripts: { preinstall: 'echo hi' } }),
  );
  await writeFile(join(dir, 'package-lock.json'), '{');
  await writeFile(join(dir, 'app.js'), 'const n = 1;\n');
  return dir;
}

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('phase 529 unparsed lockfile', () => {
  it('still reports the install script when package-lock.json does not parse', async () => {
    const cwd = await tree();
    const result = await scan({ cwd, offline: true });
    expect(result.findings.map((finding) => finding.ruleId)).toContain('CONFIG-INSTALLSCRIPT-001');
  });

  it('parses an empty lock object and does not throw', () => {
    expect(parseLockfileGraph('package-lock.json', '{}').packages).toEqual([]);
    expect(parseLockfileGraph('npm-shrinkwrap.json', '{').packages).toEqual([]);
    expect(parseLockfileGraph('yarn.lock', '{').packages).toEqual([]);
    expect(parseLockfileGraph('pnpm-lock.yaml', '{').packages).toEqual([]);
  });

  it('completes when a workspace lockfile does not parse', async () => {
    const cwd = await tree();
    await mkdir(join(cwd, 'pkg'));
    await writeFile(join(cwd, 'pkg', 'package-lock.json'), '{');
    await writeFile(join(cwd, 'package.json'), JSON.stringify({
      name: 'broken-lock',
      version: '1.0.0',
      scripts: { preinstall: 'echo hi' },
      workspaces: ['pkg'],
    }));
    process.env.FULLSHIELD_EXPERIMENTAL_WORKSPACES = '1';
    const result = await scan({ cwd, offline: true });
    expect(result.findings.map((finding) => finding.ruleId)).toContain('CONFIG-INSTALLSCRIPT-001');
  });

  it('sorts two scans of the broken tree to the same bytes', async () => {
    const cwd = await tree();
    const first = await scan({ cwd, offline: true });
    const second = await scan({ cwd, offline: true });
    const ids = (findings: typeof first.findings) => findings.map((finding) => finding.id).sort();
    expect(ids(first.findings)).toEqual(ids(second.findings));
  });

  it('leaves clean-app at 0 findings', async () => {
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });
});
