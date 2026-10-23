import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

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
