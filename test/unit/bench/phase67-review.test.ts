import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { refused, runReview } from '../../../bench/review-cli.mjs';
import { packBudgetErrors } from '../../../scripts/release-checks.mjs';

describe('phase 67 review cli', () => {
  const dirs: string[] = [];

  afterEach(async () => {
    await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('confirms, requires a reason to reject, resumes after quit, and refuses a non-TTY without writing', async () => {
    const root = await mkdtemp(join(tmpdir(), 'fs-review-'));
    dirs.push(root);
    const app = join(root, 'demo');
    await mkdir(app);
    const gt = {
      reviewed: false,
      app: 'demo',
      entries: [
        { class: 'sqli', file: 'a.js', line: 1, source: 'https://example.com/a', inScope: true },
        { class: 'xss', file: 'b.js', line: 2, source: 'https://example.com/b', inScope: true },
      ],
    };
    await writeFile(join(app, 'ground-truth.json'), `${JSON.stringify(gt, null, 2)}\n`);
    await writeFile(join(app, 'a.js'), 'one\n');
    await writeFile(join(app, 'b.js'), 'two\n');
    const before = await readFile(join(app, 'ground-truth.json'), 'utf8');

    expect(() =>
      runReview({ root, app: 'demo', mode: 'ground-truth', lines: [], tty: false, reviewerDefault: 'Ada', env: {} }),
    ).toThrow(/not a TTY/);
    expect(await readFile(join(app, 'ground-truth.json'), 'utf8')).toBe(before);
    expect(refused({ CI: '1' }, true)).toMatch(/CI/);

    runReview({ root, app: 'demo', mode: 'ground-truth', lines: ['y', 'q'], tty: true, reviewerDefault: 'Ada', env: {} });
    const mid = JSON.parse(await readFile(join(app, 'review-log.json'), 'utf8')) as { decisions: unknown[] };
    expect(mid.decisions).toHaveLength(1);
    expect(JSON.parse(await readFile(join(app, 'ground-truth.json'), 'utf8')).reviewed).toBe(false);

    expect(() =>
      runReview({ root, app: 'demo', mode: 'ground-truth', lines: ['n', ''], tty: true, reviewerDefault: 'Ada', env: {} }),
    ).toThrow(/reason/);

    runReview({
      root,
      app: 'demo',
      mode: 'ground-truth',
      lines: ['n', 'not a sink', 'demo'],
      tty: true,
      reviewerDefault: 'Ada',
      env: {},
    });
    expect(JSON.parse(await readFile(join(app, 'ground-truth.json'), 'utf8')).reviewed).toBe(true);
  });

  it('writes a findings label and keeps the review cli out of the package', async () => {
    const root = await mkdtemp(join(tmpdir(), 'fs-review-'));
    dirs.push(root);
    await mkdir(join(root, 'review'), { recursive: true });
    const csv = join(root, 'review', 'demo.csv');
    await writeFile(csv, 'id,ruleId,severity,file,line,snippet,message,label,reviewer,note\n1,SAST-SQLI-001,high,a.js,1,snippet,message,,,\n');
    runReview({ root, app: 'demo', mode: 'findings', lines: ['TP', 'looks real'], tty: true, reviewerDefault: 'Ada', env: {} });
    const text = await readFile(csv, 'utf8');
    expect(text).toContain('TP');
    expect(text).toContain('Ada');
    expect(text).toContain('looks real');
    const errors = packBudgetErrors({
      unpackedBytes: 1,
      fileCount: 1,
      hardDeps: [],
      previousHardDeps: [],
      packedFiles: ['package/bench/review-cli.mjs'],
    });
    expect(errors.some((error) => error.includes('bench/review-cli'))).toBe(true);
  });
});
