import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase474-fnmine.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_FNMINE = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_FNMINE;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

const source = "'use strict';\nfunction handler(req) {\n  db.query('SELECT * FROM users WHERE id = ' + req.query.id);\n}\n";

describe('phase 474 miss list', () => {
  it('does not list a planted bug the scan finds, including a three-line offset', () => {
    const dir = join(tmpdir(), 'fs474-hit');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'app.js'), source);
    const list = join(dir, 'list.json');
    writeFileSync(
      list,
      JSON.stringify({
        outOfScope: ['style'],
        items: [
          { id: 'local-hit', file: 'app.js', line: 3, class: 'SAST-SQLI-001' },
          { id: 'local-near', file: 'app.js', line: 6, class: 'SAST-SQLI-001' },
          { id: 'local-style', file: 'app.js', line: 1, class: 'style' },
        ],
      }),
    );
    const result = run(['--dir', dir, '--list', list], true);
    expect(result.status).toBe(0);
    const doc = JSON.parse(result.stdout) as { unreviewed: boolean; misses: Array<{ id: string }>; outOfScope: Array<{ id: string }> };
    expect(doc.unreviewed).toBe(true);
    expect(doc.misses.map((row) => row.id)).not.toContain('local-hit');
    expect(doc.misses.map((row) => row.id)).not.toContain('local-near');
    expect(doc.outOfScope.map((row) => row.id)).toContain('local-style');
    expect(doc.misses.map((row) => row.id)).not.toContain('local-style');
  }, 30_000);

  it('lists an in-scope bug four lines away', () => {
    const dir = join(tmpdir(), 'fs474-miss');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'app.js'), source);
    const list = join(dir, 'list.json');
    writeFileSync(list, JSON.stringify({ items: [{ id: 'local-far', file: 'app.js', line: 7, class: 'SAST-SQLI-001' }] }));
    const result = run(['--dir', dir, '--list', list], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('local-far');
    const phase = readFileSync(join(root, 'src', 'phases', 'p474.ts'), 'utf8');
    expect(phase.includes('node:http')).toBe(false);
    expect(phase.includes('fetch(')).toBe(false);
  }, 30_000);

  it('does nothing when the flag is off', () => {
    const result = run(['--dir', root, '--list', 'nope.json'], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
