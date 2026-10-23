import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase471-benchhtml.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_BENCHHTML = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_BENCHHTML;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 471 benchmark html', () => {
  it('shows a fixture number, the unreviewed bit, and the mtime', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs471-'));
    const file = join(dir, 'bench.json');
    writeFileSync(file, JSON.stringify({ unreviewed: true, value: 42 }));
    const mtime = statSync(file).mtime.toISOString();
    const result = run(['--file', file], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('42');
    expect(result.stdout).toContain('unreviewed: true');
    expect(result.stdout).toContain(mtime);
    expect(result.stdout.includes('<script')).toBe(false);
    expect(result.stdout.includes('src="http')).toBe(false);
  });

  it('says missing for an absent file and does not print 0 for that section', () => {
    const missing = join(tmpdir(), 'fs471-missing.json');
    const result = run(['--file', missing], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('missing');
    const section = result.stdout.split('<section')[1] ?? '';
    expect(section.includes('>0<')).toBe(false);
    const source = readFileSync(script, 'utf8');
    expect(source.includes('scan(')).toBe(false);
  });

  it('does nothing when the flag is off', () => {
    const result = run(['--file', 'nope.json'], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
