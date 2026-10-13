import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

const root = process.cwd();
const cliPath = join(root, 'dist', 'cli', 'index.js');
const vulnerableApp = join(root, 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(root, 'test', 'fixtures', 'clean-app');

// Assembled at test time; never committed as a literal.
const RAW_SECRETS = [
  'AKIA' + 'IOSFODNN7EXAMPLE',
  'sk_test_' + 'FAKEfakeFAKEfakeFAKE1234',
  'fake-password' + '-fixture',
];

interface JsonReport {
  findings: Array<{ ruleId: string; severity: string; snippet?: string }>;
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

describe('secrets module via built CLI', () => {
  it('finds all seeded secrets in vulnerable-app with --modules secrets', () => {
    const { stdout } = runCli(['scan', vulnerableApp, '--modules', 'secrets', '--json']);
    const report = JSON.parse(stdout) as JsonReport;
    const ruleIds = new Set(report.findings.map((f) => f.ruleId));
    for (const id of [
      'SECRET-AWS-001',
      'SECRET-STRIPE-001',
      'SECRET-JWT-001',
      'SECRET-DBURL-001',
      'SECRET-ENVFILE-001',
    ]) {
      expect(ruleIds, `expected ${id}`).toContain(id);
    }
  });

  it('exits 1 on vulnerable-app with --fail-on high (gate is live from phase 2)', () => {
    const { status } = runCli(['scan', vulnerableApp, '--modules', 'secrets', '--fail-on', 'high']);
    expect(status).toBe(1);
  });

  it('reports zero secrets findings on clean-app', () => {
    const { status, stdout } = runCli(['scan', cleanApp, '--modules', 'secrets', '--json']);
    const report = JSON.parse(stdout) as JsonReport;
    expect(report.summary.total).toBe(0);
    expect(status).toBe(0);
  });

  it('never emits a raw secret in human or JSON output', () => {
    const human = runCli(['scan', vulnerableApp, '--modules', 'secrets']);
    const json = runCli(['scan', vulnerableApp, '--modules', 'secrets', '--json']);
    for (const raw of RAW_SECRETS) {
      expect(human.stdout).not.toContain(raw);
      expect(json.stdout).not.toContain(raw);
    }
    // Masked forms are present instead.
    expect(json.stdout).toContain('AKIA****');
  });
});
