import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';

import { afterEach, describe, expect, it } from 'vitest';

import { copiedSnippets, enabled, FLAG, indexedNodeCounts, indexReviewed, NORMALIZATION_RULES } from '../../../src/phases/p372.js';

const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

function big(name: string): string {
  const names = Array.from({ length: 25 }, (_unused, index) => `n${index}`);
  return `function ${name}(${names.join(',')}) { return ${names.join(' + ')}; }\n`;
}

describe('phase 372 copied snippets', () => {
  it('lists the normalization rules', () => {
    expect(NORMALIZATION_RULES).toEqual([
      'Identifier names become id',
      'Literal values become lit',
      'Template quasis become lit',
      'Node type and child order are preserved',
    ]);
  });

  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(indexReviewed([])).toEqual([]);
    expect(copiedSnippets([], [{ path: 'app.js', source: big('reviewed') }])).toEqual([]);
  });

  it('does not index a 10-node function', () => {
    process.env[FLAG] = '1';
    expect(indexedNodeCounts('function tiny(a) { return a; }')).toEqual([]);
  });

  it('reports a copied body at 40 nodes and ignores a non-match', () => {
    process.env[FLAG] = '1';
    const source = big('reviewed');
    expect(indexedNodeCounts(source)[0]).toBeGreaterThanOrEqual(40);
    const index = indexReviewed(
      [{ osvId: 'FIXTURE-OSV', reviewed: true, bodyPath: 'ignored' }],
      () => source,
    );
    expect(index).toHaveLength(1);
    const hit = copiedSnippets(index, [
      { path: 'app.js', source },
      { path: 'other.js', source: 'function other(a) { return a + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10 + 11 + 12 + 13 + 14 + 15 + 16 + 17 + 18 + 19 + 20 + 21 + 22 + 23 + 24; }' },
    ]);
    expect(hit.some((row) => row.file === 'app.js' && row.osvId === 'FIXTURE-OSV' && row.severity === 'info')).toBe(true);
    expect(hit.find((row) => row.file === 'app.js')?.message).not.toContain('exploitable');
    expect(hit.some((row) => row.file === 'other.js')).toBe(false);
  });

  it('does not index an unreviewed row and does not search node_modules', async () => {
    process.env[FLAG] = '1';
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-p372-'));
    dirs.push(dir);
    const body = join(dir, 'body.js');
    await writeFile(body, big('reviewed'));
    expect(indexReviewed([{ osvId: 'FIXTURE-OSV', reviewed: false, bodyPath: body }])).toEqual([]);
    const index = indexReviewed([{ osvId: 'FIXTURE-OSV', reviewed: true, bodyPath: body }]);
    expect(copiedSnippets(index, [{ path: 'node_modules/pkg/index.js', source: big('reviewed') }])).toEqual([]);
    expect(
      copiedSnippets(index, [{ path: 'vendor/pkg/index.js', source: big('reviewed') }], ['vendor/']),
    ).toHaveLength(1);
    const text = await readFile(body, 'utf8');
    expect(text.length).toBeGreaterThan(0);
  });

  it('does not fetch', () => {
    const source = readFileSync(new URL('../../../src/phases/p372.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('node:http');
    expect(source).not.toContain('node:https');
  });
});
