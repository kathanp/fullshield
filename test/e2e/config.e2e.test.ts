import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

const root = process.cwd();
const cliPath = join(root, 'dist', 'cli', 'index.js');
const vulnerableApp = join(root, 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(root, 'test', 'fixtures', 'clean-app');

function runCli(args: string[]): { status: number | null; stdout: string } {
  const result = spawnSync(process.execPath, [cliPath, ...args], { encoding: 'utf8' });
  return { status: result.status, stdout: result.stdout };
}

beforeAll(() => {
  if (!existsSync(cliPath)) throw new Error('built CLI missing');
});

describe('config + remaining sast via built CLI', () => {
  it('finds Phase-5 SAST and config rule ids in vulnerable-app', () => {
    const { stdout } = runCli(['scan', vulnerableApp, '--json']);
    const report = JSON.parse(stdout) as { findings: Array<{ ruleId: string }> };
    const ids = new Set(report.findings.map((f) => f.ruleId));
    for (const id of [
      'SAST-NOSQLI-001',
      'SAST-SSRF-001',
      'SAST-REDIRECT-001',
      'SAST-PROTO-001',
      'SAST-XSS-001',
      'SAST-AUTH-001',
      'CONFIG-HELMET-001',
      'CONFIG-CORS-001',
      'CONFIG-DOCKER-LATEST-001',
    ]) {
      expect(ids, `expected ${id}`).toContain(id);
    }
  });

  it('clean-app still has zero high/critical findings', () => {
    const { status, stdout } = runCli(['scan', cleanApp, '--fail-on', 'high', '--json']);
    const report = JSON.parse(stdout) as {
      findings: Array<{ severity: string }>;
    };
    expect(report.findings.every((f) => !['high', 'critical'].includes(f.severity))).toBe(true);
    expect(status).toBe(0);
  });
});
