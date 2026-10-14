import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const cli = join(root, 'dist', 'cli', 'index.js');

describe('Phase 20 CLI confirm (built)', () => {
  it('refuses confirm without FULLSHIELD_EXPERIMENTAL_CONFIRM', () => {
    const result = spawnSync(process.execPath, [cli, 'confirm', 'http://127.0.0.1:1/'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, FULLSHIELD_EXPERIMENTAL_CONFIRM: '' },
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/FULLSHIELD_EXPERIMENTAL_CONFIRM/);
  });

  it('refuses a public hostname even with experimental set', () => {
    const result = spawnSync(process.execPath, [cli, 'confirm', 'http://example.com/'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, FULLSHIELD_EXPERIMENTAL_CONFIRM: '1' },
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/refused/);
  });

  it('refuses IPv6 and non-127.0.0.1 literals', () => {
    for (const url of ['http://[::1]/', 'http://[2001:db8::1]/', 'http://8.8.8.8/']) {
      const result = spawnSync(process.execPath, [cli, 'confirm', url], {
        cwd: root,
        encoding: 'utf8',
        env: { ...process.env, FULLSHIELD_EXPERIMENTAL_CONFIRM: '1' },
      });
      expect(result.status).toBe(2);
      expect(result.stderr).toMatch(/refused/);
    }
  });
});
