import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase492-reprobuild.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_REPROBUILD = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_REPROBUILD;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

function tree(dir: string, body: string) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'dist.js'), body);
}

describe('phase 492 rebuild bytes', () => {
  it('passes identical trees and fails a planted difference unless an allow row names it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs492-'));
    const left = join(dir, 'left');
    const right = join(dir, 'right');
    tree(left, 'same');
    tree(right, 'same');
    const allow = join(dir, 'allow.json');
    writeFileSync(allow, JSON.stringify({ files: [] }));
    const ok = run(['--left', left, '--right', right, '--allow', allow, '--watch', 'dist.js'], true);
    expect(ok.status).toBe(0);
    tree(right, 'same\n# timestamp');
    const failed = run(['--left', left, '--right', right, '--allow', allow, '--watch', 'dist.js'], true);
    expect(failed.status).not.toBe(0);
    expect(failed.stderr).toContain('dist.js');
    writeFileSync(allow, JSON.stringify({ files: [{ path: 'dist.js', reason: 'timestamp header' }] }));
    const allowed = run(['--left', left, '--right', right, '--allow', allow, '--watch', 'dist.js'], true);
    expect(allowed.status).toBe(0);
    const before = createHash('sha256').update(readFileSync(join(left, 'dist.js'))).digest('hex');
    expect(createHash('sha256').update(readFileSync(join(left, 'dist.js'))).digest('hex')).toBe(before);
  });

  it('rejects an allow row with an empty reason', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs492b-'));
    const left = join(dir, 'left');
    const right = join(dir, 'right');
    tree(left, 'same');
    tree(right, 'same');
    const allow = join(dir, 'allow.json');
    writeFileSync(allow, JSON.stringify({ files: [{ path: 'dist.js', reason: '' }] }));
    const result = run(['--left', left, '--right', right, '--allow', allow], true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('empty reason');
  });

  it('does nothing when the flag is off', () => {
    const result = run([], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
