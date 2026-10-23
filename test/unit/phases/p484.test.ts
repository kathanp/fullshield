import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase484-antioverfit.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_ANTIOVERFIT = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_ANTIOVERFIT;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

function setup() {
  const dir = mkdtempSync(join(tmpdir(), 'fs484-'));
  const registry = join(dir, 'holdouts.json');
  writeFileSync(
    registry,
    JSON.stringify({
      apps: [
        { name: 'nodegoat', status: 'tuning' },
        { name: 'verademo-javascript', status: 'untouched' },
      ],
    }),
  );
  return { dir, registry };
}

describe('phase 484 anti-overfitting', () => {
  it('fails a rule edit plus a NodeGoat edit without a fixture', () => {
    const { dir, registry } = setup();
    const diff = join(dir, 'diff.txt');
    writeFileSync(diff, 'M src/modules/sast/sql.ts\nM bench/nodegoat/app.js\n');
    const result = run(['--diff', diff, '--registry', registry, '--root', dir], true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('a handwritten fixture under test/fixtures/ is required');
  });

  it('passes the same diff when a handwritten fixture is included', () => {
    const { dir, registry } = setup();
    const diff = join(dir, 'diff.txt');
    writeFileSync(diff, 'M src/modules/sast/sql.ts\nM bench/nodegoat/app.js\nA test/fixtures/hand/sql.js\n');
    const result = run(['--diff', diff, '--registry', registry, '--root', dir], true);
    expect(result.status).toBe(0);
  });

  it('fails an untouched results file and a fixture that copies tuning bytes', () => {
    const { dir, registry } = setup();
    const added = join(dir, 'added.txt');
    writeFileSync(added, 'A bench/verademo-javascript/scan.json\n');
    const untouched = run(['--diff', added, '--registry', registry, '--root', dir], true);
    expect(untouched.status).not.toBe(0);
    expect(untouched.stderr).toContain('untouched results file');
    mkdirSync(join(dir, 'bench', 'nodegoat'), { recursive: true });
    mkdirSync(join(dir, 'test', 'fixtures', 'hand'), { recursive: true });
    writeFileSync(join(dir, 'bench', 'nodegoat', 'app.js'), 'SAME');
    writeFileSync(join(dir, 'test', 'fixtures', 'hand', 'copy.js'), 'SAME');
    const copy = join(dir, 'copy.txt');
    writeFileSync(copy, 'A test/fixtures/hand/copy.js\n');
    const copied = run(['--diff', copy, '--registry', registry, '--root', dir], true);
    expect(copied.status).not.toBe(0);
    expect(copied.stderr).toContain('copies tuning-app bytes');
  });
});
