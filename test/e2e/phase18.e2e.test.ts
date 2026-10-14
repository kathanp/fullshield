import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const cli = join(root, 'dist', 'cli', 'index.js');

describe('Phase 18 CLI (built)', () => {
  it('refuses honey init and emit-virtual-patches without experimental env', () => {
    const honey = spawnSync(process.execPath, [cli, 'honey', 'init'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, FULLSHIELD_EXPERIMENTAL_HONEY: '' },
    });
    expect(honey.status).toBe(2);
    const vpatch = spawnSync(
      process.execPath,
      [cli, 'scan', join(root, 'test', 'fixtures', 'clean-app'), '--offline', '--emit-virtual-patches'],
      { cwd: root, encoding: 'utf8', env: { ...process.env, FULLSHIELD_EXPERIMENTAL_VPATCH: '' } },
    );
    expect(vpatch.status).toBe(2);
  });

  it('writes honeytokens and vpatches when experimental flags are set', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-p18-'));
    try {
      const honey = spawnSync(process.execPath, [cli, 'honey', 'init', dir], {
        cwd: root,
        encoding: 'utf8',
        env: { ...process.env, FULLSHIELD_EXPERIMENTAL_HONEY: '1' },
      });
      expect(honey.status).toBe(0);
      expect(existsSync(join(dir, '.env.backup'))).toBe(true);
      const vuln = join(root, 'test', 'fixtures', 'vulnerable-app');
      const out = join(dir, 'vpatches.json');
      const vpatch = spawnSync(
        process.execPath,
        [cli, 'scan', vuln, '--offline', '--modules', 'sast', '--emit-virtual-patches', out],
        { cwd: root, encoding: 'utf8', env: { ...process.env, FULLSHIELD_EXPERIMENTAL_VPATCH: '1' } },
      );
      expect(vpatch.status === 0 || vpatch.status === 1).toBe(true);
      const raw = JSON.parse(readFileSync(out, 'utf8')) as { patches: Array<{ ruleId: string }> };
      expect(raw.patches.length).toBeGreaterThan(0);
      expect(raw.patches.some((p) => p.ruleId.startsWith('SAST-'))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
