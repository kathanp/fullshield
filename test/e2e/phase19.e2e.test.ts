import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const cli = join(root, 'dist', 'cli', 'index.js');

describe('Phase 19 CLI install-guard (built)', () => {
  it('refuses install without FULLSHIELD_EXPERIMENTAL_SUPPLY', () => {
    const result = spawnSync(process.execPath, [cli, 'install', 'lodash'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, FULLSHIELD_EXPERIMENTAL_SUPPLY: '' },
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/FULLSHIELD_EXPERIMENTAL_SUPPLY/);
  });

  it('analyzes a local fixture dir and does not spawn npm when findings exist', () => {
    const fixture = join(root, 'test', 'fixtures', 'supply', 'malicious-pkg');
    const result = spawnSync(process.execPath, [cli, 'install', 'fullshield-seeded-malicious', '--dir', fixture], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, FULLSHIELD_EXPERIMENTAL_SUPPLY: '1' },
    });
    expect(result.status).toBe(1);
    expect(result.stdout).toMatch(/SUPPLY-NPMRC-NET-001/);
    expect(result.stdout).not.toMatch(/npm install/);
  });
});
