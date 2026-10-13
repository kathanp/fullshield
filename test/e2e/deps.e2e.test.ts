import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

const root = process.cwd();
const cliPath = join(root, 'dist', 'cli', 'index.js');
const vulnerableApp = join(root, 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(root, 'test', 'fixtures', 'clean-app');

interface JsonReport {
  findings: Array<{ ruleId: string; snippet?: string; message: string; severity: string }>;
  summary: { total: number };
}

function runCli(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [cliPath, ...args], { encoding: 'utf8' });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

beforeAll(() => {
  if (!existsSync(cliPath)) {
    throw new Error(`built CLI not found at ${cliPath} — run \`npm run build\` first`);
  }
});

describe('deps module via built CLI', () => {
  it('finds seeded vulnerable lodash/minimist and the expresss typosquat offline', () => {
    const { status, stdout, stderr } = runCli([
      'scan',
      vulnerableApp,
      '--modules',
      'deps',
      '--offline',
      '--json',
    ]);
    expect(stderr).toBe('');
    const report = JSON.parse(stdout) as JsonReport;
    const blob = JSON.stringify(report.findings);
    expect(blob).toContain('DEPS-VULN-001');
    expect(blob).toContain('lodash@4.17.11');
    expect(blob).toContain('minimist@1.2.0');
    expect(blob).toContain('DEPS-TYPOSQUAT-001');
    expect(blob).toContain('expresss');
    expect(status).toBe(1);
  });

  it('reports zero deps findings on clean-app', () => {
    const { status, stdout } = runCli(['scan', cleanApp, '--modules', 'deps', '--json']);
    const report = JSON.parse(stdout) as JsonReport;
    expect(report.summary.total).toBe(0);
    expect(status).toBe(0);
  });
});
