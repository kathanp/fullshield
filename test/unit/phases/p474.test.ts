import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import { main, mine } from '../../../src/phases/p474.js';

const FNMINE = 'FULLSHIELD_EXPERIMENTAL_FNMINE';

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
const script = join(root, 'scripts', 'phase474-fnmine.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_FNMINE = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_FNMINE;}
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

describe('phase 474 module', () => {
  it('mines a list through the exported functions', async () => {
    process.env[FNMINE] = '1';
    try {
      const dir = join(tmpdir(), 'fs474-mod');
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, 'app.js'), source);
      const list = join(dir, 'list.json');
      const items = {
        items: [
          { id: 'local-hit', file: 'app.js', line: 3, class: 'SAST-SQLI-001' },
          { id: 'local-cwe', file: 'app.js', line: 3, class: 'CWE-89' },
          { id: 'local-far', file: 'app.js', line: 7, class: 'SAST-SQLI-001' },
          { id: 'local-other', file: 'missing.js', line: 3, class: 'SAST-SQLI-001' },
          { id: 'local-style', file: 'app.js', line: 1, class: 'style' },
        ],
      };
      writeFileSync(list, JSON.stringify({ ...items, outOfScope: ['style'] }));
      const result = await capture(() => main(['--dir', dir, '--list', list]));
      expect(result.code).toBe(0);
      const doc = JSON.parse(result.stdout) as { misses: Array<{ id: string }>; outOfScope: Array<{ id: string }> };
      expect(doc.misses.map((row) => row.id)).not.toContain('local-hit');
      expect(doc.misses.map((row) => row.id)).toContain('local-far');
      expect(doc.outOfScope.map((row) => row.id)).toContain('local-style');
      const mined = JSON.parse(await mine(dir, items)) as { misses: Array<{ id: string }>; outOfScope: Array<{ id: string }> };
      expect(mined.outOfScope).toEqual([]);
      expect(mined.misses.map((row) => row.id)).toContain('local-style');
      expect(mined.misses.map((row) => row.id)).toContain('local-other');
      expect((await capture(() => main(['--dir', dir]))).code).toBe(2);
      expect((await capture(() => main([]))).code).toBe(2);
      expect((await capture(() => main(['--list', list]))).code).toBe(2);
    } finally {
      delete process.env[FNMINE];
    }
  }, 60_000);
});
