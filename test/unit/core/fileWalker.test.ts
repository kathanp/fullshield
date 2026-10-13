import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { walkFiles } from '../../../src/core/fileWalker.js';

let dir: string;

async function seed(relPath: string, contents = ''): Promise<void> {
  const full = join(dir, ...relPath.split('/'));
  await mkdir(join(full, '..'), { recursive: true });
  await writeFile(full, contents);
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'fullshield-walk-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('walkFiles', () => {
  it('lists files recursively as sorted posix-relative paths', async () => {
    await seed('b.txt');
    await seed('src/index.ts');
    await seed('src/deep/nested.ts');
    const files = await walkFiles({ cwd: dir });
    expect(files).toEqual(['b.txt', 'src/deep/nested.ts', 'src/index.ts']);
  });

  it('always ignores node_modules and .git', async () => {
    await seed('node_modules/pkg/index.js');
    await seed('.git/HEAD');
    await seed('app.ts');
    const files = await walkFiles({ cwd: dir });
    expect(files).toEqual(['app.ts']);
  });

  it('respects .gitignore at the scan root', async () => {
    await seed('.gitignore', 'ignored-dir/\n*.log\n');
    await seed('ignored-dir/secret.txt');
    await seed('debug.log');
    await seed('kept.ts');
    const files = await walkFiles({ cwd: dir });
    expect(files).toEqual(['.gitignore', 'kept.ts']);
  });

  it('respects config ignore globs on top of .gitignore', async () => {
    await seed('dist/out.js');
    await seed('src/a.test.ts');
    await seed('src/a.ts');
    const files = await walkFiles({ cwd: dir, ignore: ['dist/**', '**/*.test.ts'] });
    expect(files).toEqual(['src/a.ts']);
  });

  it('includes dotfiles such as committed .env files', async () => {
    await seed('.env', 'FAKE=1');
    const files = await walkFiles({ cwd: dir });
    expect(files).toEqual(['.env']);
  });
});
