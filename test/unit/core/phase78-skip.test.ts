import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';

const dirs: string[] = [];

afterEach(async () => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_PERF2;
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function fixture(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fs-perf2-'));
  dirs.push(dir);
  await mkdir(join(dir, 'src'), { recursive: true });
  await mkdir(join(dir, 'dist'), { recursive: true });
  await writeFile(
    join(dir, 'src', 'app.js'),
    'const db = { query() {} };\nfunction go(req) { db.query("SELECT " + req.query.id); }\n',
  );
  await writeFile(join(dir, 'src', 'types.d.ts'), 'export const secret = "AKIA" + "IOSFODNN7EXAMPLEXX";\n');
  await writeFile(join(dir, 'dist', 'bundle.js'), 'db.query("SELECT " + req.query.id);\n');
  await writeFile(join(dir, 'src', 'app.js.map'), '{"version":3,"sources":["app.js"]}\n');
  await writeFile(join(dir, 'src', 'min.js'), `${'a'.repeat(50_001)}\n`);
  await writeFile(
    join(dir, 'fullshield.config.json'),
    JSON.stringify({ modules: ['sast'], defaultExcludes: false, ignore: [] }),
  );
  return dir;
}

describe('phase 78 step 2 skip non-source', () => {
  it('leaves default scan metadata unchanged when the flag is off', async () => {
    const cwd = await fixture();
    const off = await scan({ cwd, modules: ['sast'], offline: true });
    expect(off.metadata.skipped).toBeUndefined();
    expect(off.findings.some((finding) => finding.file === 'src/app.js' && finding.ruleId === 'SAST-SQLI-001')).toBe(true);
  });

  it('counts skipped generated, declaration, map, and minified files only when the flag is on', async () => {
    const cwd = await fixture();
    process.env.FULLSHIELD_EXPERIMENTAL_PERF2 = '1';
    const on = await scan({ cwd, modules: ['sast'], offline: true });
    expect(on.findings.some((finding) => finding.file === 'src/app.js' && finding.ruleId === 'SAST-SQLI-001')).toBe(true);
    expect(on.findings.some((finding) => finding.file === 'dist/bundle.js')).toBe(false);
    expect(on.metadata.skipped).toEqual({
      total: 4,
      oversize: 0,
      minified: 1,
      declaration: 1,
      sourceMap: 1,
      generated: 1,
    });
  });
});
