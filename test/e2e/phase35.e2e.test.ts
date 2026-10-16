import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const cli = join(root, 'dist', 'cli', 'index.js');
const cleanApp = join(root, 'test', 'fixtures', 'clean-app');
const vulnerableApp = join(root, 'test', 'fixtures', 'vulnerable-app');

function run(args: string[], env: NodeJS.ProcessEnv = process.env) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    encoding: 'utf8',
    env,
  });
}

describe('Phase 35 CLI host (built binary, no live-host assertions)', () => {
  it('refuses host without --experimental-host', () => {
    const result = run(['host'], { ...process.env, FULLSHIELD_EXPERIMENTAL_HOST: '' });
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/experimental-host/);
  });

  it('host --help documents --experimental-host', () => {
    const result = run(['host', '--help']);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('--experimental-host');
  });

  it('default scan never emits HOST-* findings', () => {
    for (const app of [cleanApp, vulnerableApp]) {
      const result = run(['scan', app, '--json', '--offline']);
      const report = JSON.parse(result.stdout) as { findings: Array<{ ruleId: string }> };
      expect(report.findings.some((f) => f.ruleId.startsWith('HOST-'))).toBe(false);
    }
  }, 20_000);

  it('host --experimental-host never requests sudo', () => {
    const result = run(['host', '--experimental-host', '--json']);
    const blob = `${result.stdout}\n${result.stderr}`;
    expect(blob).not.toMatch(/\bsudo\b/);
    if (process.platform === 'darwin' || process.platform === 'win32') {
      expect(result.status).toBe(0);
      expect(blob).toMatch(/skipped/i);
    }
  });
});
