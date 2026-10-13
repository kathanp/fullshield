import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

const root = process.cwd();
const cliPath = join(root, 'dist', 'cli', 'index.js');
const vulnerableApp = join(root, 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(root, 'test', 'fixtures', 'clean-app');

const PHASE4 = [
  'SAST-SQLI-001',
  'SAST-CMDI-001',
  'SAST-PATH-001',
  'SAST-EVAL-001',
  'SAST-JWT-001',
  'SAST-CRYPTO-001',
];

interface JsonReport {
  findings: Array<{ ruleId: string }>;
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

describe('sast module via built CLI', () => {
  it('finds all six Phase-4 rule ids in vulnerable-app', () => {
    const { stdout } = runCli(['scan', vulnerableApp, '--modules', 'sast', '--json']);
    const report = JSON.parse(stdout) as JsonReport;
    const ids = new Set(report.findings.map((f) => f.ruleId));
    for (const id of PHASE4) {
      expect(ids, `expected ${id}`).toContain(id);
    }
  });

  it('reports zero sast findings on clean-app', () => {
    const { status, stdout } = runCli(['scan', cleanApp, '--modules', 'sast', '--json']);
    const report = JSON.parse(stdout) as JsonReport;
    expect(report.summary.total).toBe(0);
    expect(status).toBe(0);
  });
});
