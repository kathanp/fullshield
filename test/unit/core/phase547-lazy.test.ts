import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import { takeLastTaintWalk } from '../../../src/modules/sast/lazy-taint.js';

const dirs: string[] = [];

afterEach(async () => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_PERF2;
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('phase 547 lazy taint on every scan', () => {
  it('walks a source and its import without PERF2, and skips an unrelated file', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fs-547-'));
    dirs.push(cwd);
    await mkdir(join(cwd, 'src'));
    await writeFile(
      join(cwd, 'src', 'lib.js'),
      'function build(id) { return "SELECT " + id; }\nmodule.exports = { build };\n',
    );
    await writeFile(
      join(cwd, 'src', 'app.js'),
      'const { build } = require("./lib");\nfunction go(req) { db.query("SELECT " + req.query.id); build(req.query.id); }\n',
    );
    await writeFile(join(cwd, 'src', 'plain.js'), 'function add(a, b) { return a + b; }\n');
    const result = await scan({ cwd, modules: ['sast'], offline: true });
    expect(result.findings.some((finding) => finding.ruleId === 'SAST-SQLI-001')).toBe(true);
    const walked = takeLastTaintWalk();
    expect(walked).toContain('src/app.js');
    expect(walked).toContain('src/lib.js');
    expect(walked).not.toContain('src/plain.js');
  });
});
