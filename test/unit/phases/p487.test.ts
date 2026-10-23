import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase487-fixpipe.mjs');
const vitestConfig = join(root, 'vitest.config.ts');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_FIXPIPE = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_FIXPIPE;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 487 candidate fixtures', () => {
  it('writes a candidate the default runner does not load', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs487-'));
    const feedback = join(dir, 'feedback.json');
    writeFileSync(
      feedback,
      JSON.stringify({ fingerprint: 'abc', witness: [{ file: 'test/fixtures/hand/a.js', line: 1 }], note: 'fp' }),
    );
    const before = createHash('sha256').update(readFileSync(vitestConfig)).digest('hex');
    const result = run(['--feedback', feedback, '--root', dir], true);
    expect(result.status).toBe(0);
    const meta = JSON.parse(readFileSync(join(dir, 'test', 'fixtures', 'candidates', 'abc', 'meta.json'), 'utf8')) as {
      reviewed: boolean;
    };
    expect(meta.reviewed).toBe(false);
    const includes = run(['--print-includes'], true);
    expect(includes.stdout.includes('candidates/')).toBe(false);
    expect(createHash('sha256').update(readFileSync(vitestConfig)).digest('hex')).toBe(before);
  });

  it('writes a TODO for a tuning-app witness and does not copy that source', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs487b-'));
    const secret = 'tuning-source-bytes-unique';
    const feedback = join(dir, 'feedback.json');
    writeFileSync(
      feedback,
      JSON.stringify({ fingerprint: 'bench1', witness: [{ file: 'bench/nodegoat/app.js', line: 2 }], note: secret }),
    );
    const result = run(['--feedback', feedback, '--root', dir], true);
    expect(result.status).toBe(0);
    const todo = readFileSync(join(dir, 'test', 'fixtures', 'candidates', 'bench1', 'TODO.txt'), 'utf8');
    expect(todo).toContain('TODO');
    expect(todo.includes(secret)).toBe(false);
    const source = readFileSync(script, 'utf8');
    expect(source.includes('node:http')).toBe(false);
    expect(source.includes('fetch(')).toBe(false);
  });

  it('does nothing when the flag is off', () => {
    const result = run(['--print-includes'], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
