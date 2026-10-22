import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase490-auditpack.mjs');
const token = 'AKIAIOSFODNN7EXAMPLE';

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_AUDITPACK = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_AUDITPACK;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 490 evidence pack', () => {
  it('writes the sentence on line 1 and the scan JSON, and names a missing SBOM', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs490-'));
    const out = join(dir, 'pack');
    const scan = join(dir, 'scan.json');
    writeFileSync(scan, JSON.stringify({ findings: [{ message: token }] }));
    const threat = join(dir, 'threat.md');
    writeFileSync(threat, '# Threat model\n## Assets\n');
    const result = run(['--out', out, '--scan', scan, '--threat', threat], true);
    expect(result.status).toBe(0);
    const readme = readFileSync(join(out, 'README.md'), 'utf8').split('\n');
    expect(readme[0]).toBe('The contents are locally generated and are not a third-party assessment.');
    expect(readme.join('\n')).toContain('missing SBOM');
    expect(existsSync(join(out, 'sbom.json'))).toBe(false);
    expect(existsSync(join(out, 'scan.json'))).toBe(true);
    expect(readFileSync(join(out, 'scan.json'), 'utf8').includes(token)).toBe(false);
    expect(readFileSync(join(out, 'threat-headings.md'), 'utf8')).toContain('## Assets');
  });

  it('exits FS-E when the flag is off and does not create the folder', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs490b-'));
    const out = join(dir, 'pack');
    const result = run(['--out', out, '--scan', join(dir, 'missing.json')], false);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('FS-E');
    expect(existsSync(out)).toBe(false);
    const source = readFileSync(script, 'utf8');
    expect(source.includes('node:http')).toBe(false);
    expect(source.includes('fetch(')).toBe(false);
  });
});
