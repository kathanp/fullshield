import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import { lastParseCounts } from '../../../src/core/shared-ast.js';

const dirs: string[] = [];

afterEach(async () => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_PERF2;
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('phase 545 shared AST on every scan', () => {
  it('parses each source file at most once without PERF2', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fs-545-'));
    dirs.push(cwd);
    await mkdir(join(cwd, 'src'));
    await writeFile(join(cwd, 'src', 'a.js'), 'function add(a, b) { return a + b; }\n');
    await writeFile(join(cwd, 'src', 'b.js'), 'const { add } = require("./a");\nfunction go(req) { return add(req.query.id, 1); }\n');
    await scan({ cwd, offline: true });
    const counts = lastParseCounts();
    expect(counts.get('src/a.js')).toBe(1);
    expect(counts.get('src/b.js')).toBe(1);
  });
});
