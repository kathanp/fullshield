import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import { main, NOT_ATTRIBUTED, replayDirs } from '../../../src/phases/p467.js';

const CVEREPLAY = 'FULLSHIELD_EXPERIMENTAL_CVEREPLAY';

async function capture(run: () => Promise<number>): Promise<{ code: number; stdout: string; stderr: string }> {
  let stdout = '';
  let stderr = '';
  const writeOut = process.stdout.write.bind(process.stdout);
  const writeErr = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((chunk: string | Uint8Array) => {
    stdout += String(chunk);
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: string | Uint8Array) => {
    stderr += String(chunk);
    return true;
  }) as typeof process.stderr.write;
  try {
    const code = await run();
    return { code, stdout, stderr };
  } finally {
    process.stdout.write = writeOut;
    process.stderr.write = writeErr;
  }
}

const root = process.cwd();
const script = join(root, 'scripts', 'phase467-cvereplay.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_CVEREPLAY = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_CVEREPLAY;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

function tree(name: string, source: string) {
  const dir = join(tmpdir(), name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'app.js'), source);
  return dir;
}

const twoBugs = "'use strict';\nfunction handler(req) {\n  db.query('SELECT * FROM users WHERE id = ' + req.query.id);\n  db.query('SELECT * FROM accounts WHERE id = ' + req.query.acct);\n}\n";
const clean = "'use strict';\nfunction handler(req) {\n  db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);\n}\n";

describe('phase 467 advisory replay', () => {
  it('marks a bug only in --before as present-before and lists both keys', () => {
    const before = tree('fs467-before', twoBugs);
    const after = tree('fs467-after', clean);
    const result = run(['--before', before, '--after', after, '--id', 'label-only'], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('These keys are not attributed to the id.');
    expect(result.stdout).toContain('present-before');
    const keys = result.stdout.split('\n').filter((line) => line.startsWith('present-before'));
    expect(keys.length).toBeGreaterThan(1);
  }, 30_000);

  it('marks the same bug in both trees as not-distinguishing', () => {
    const before = tree('fs467-both-a', twoBugs);
    const after = tree('fs467-both-b', twoBugs);
    const result = run(['--before', before, '--after', after, '--id', 'label-both'], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('not-distinguishing');
    expect(result.stdout.includes('present-before')).toBe(false);
  }, 30_000);

  it('does not construct an OSV client or fetch git', () => {
    const text = readFileSync(join(root, 'src', 'phases', 'p467.ts'), 'utf8');
    expect(text.includes('osv.js')).toBe(false);
    expect(text.includes('git fetch')).toBe(false);
    const off = run(['--before', root, '--after', root, '--id', 'x'], false);
    expect(off.status).toBe(0);
    expect(off.stdout).toBe('');
  });
});

describe('phase 467 module', () => {
  it('replays directories through the exported functions', async () => {
    process.env[CVEREPLAY] = '1';
    try {
      const before = tree('fs467-mod-before', twoBugs);
      const after = tree('fs467-mod-after', clean);
      const bugs = tree('fs467-mod-bugs', twoBugs);
      const safe = tree('fs467-mod-safe', clean);
      const result = await capture(() => main(['--before', before, '--after', after, '--id', 'label-only']));
      expect(result.code).toBe(0);
      expect(result.stdout).toContain(NOT_ATTRIBUTED);
      expect(result.stdout).toContain('present-before');
      expect(result.stdout).toContain('id-label: label-only');
      const same = await replayDirs(bugs, bugs, 'label-both');
      expect(same).toContain('not-distinguishing');
      expect(same.includes('present-before')).toBe(false);
      const regressed = await replayDirs(safe, bugs, 'label-regressed');
      expect(regressed).toContain('regressed');
      const usage = await capture(() => main([]));
      expect(usage.code).toBe(2);
      expect(usage.stderr).toContain('usage');
      expect((await capture(() => main(['--before', before]))).code).toBe(2);
      expect((await capture(() => main(['--before', before, '--after', after]))).code).toBe(2);
      expect((await capture(() => main(['--before', before, '--after', after, '--id']))).code).toBe(2);
    } finally {
      delete process.env[CVEREPLAY];
    }
  }, 60_000);
});
