import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { beforeAll, describe, expect, it } from 'vitest';

// E2E tests execute the BUILT binary (dist/cli/index.js), never the TS source.
const root = process.cwd();
const cliPath = join(root, 'dist', 'cli', 'index.js');
const distIndex = join(root, 'dist', 'index.js');
const vulnerableApp = join(root, 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(root, 'test', 'fixtures', 'clean-app');

// Assembled at test time so no realistic-looking key is committed (spec §14).
const FAKE_AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';

interface ExpectedFinding {
  module: string;
  ruleId: string;
}

interface JsonReport {
  findings: Array<{ ruleId: string; severity: string }>;
  summary: { total: number; bySeverity: Record<string, number> };
  metadata: { version: string; modulesRun: string[] };
}

function runCli(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [cliPath, ...args], { encoding: 'utf8' });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

let implementedModules: string[] = [];

beforeAll(async () => {
  if (!existsSync(cliPath)) {
    throw new Error(`built CLI not found at ${cliPath} — run \`npm run build\` before e2e tests`);
  }
  const dist = (await import(pathToFileURL(distIndex).href)) as {
    IMPLEMENTED_MODULES: readonly string[];
  };
  implementedModules = [...dist.IMPLEMENTED_MODULES];
});

describe('fullshield CLI (built binary)', () => {
  it('scan vulnerable-app --json emits a valid report containing every expected rule id for implemented modules', () => {
    const { status, stdout } = runCli(['scan', vulnerableApp, '--json']);
    const report = JSON.parse(stdout) as JsonReport;
    expect(Array.isArray(report.findings)).toBe(true);
    expect(report.summary.total).toBe(report.findings.length);
    expect(typeof report.metadata.version).toBe('string');

    const expected = (
      JSON.parse(readFileSync(join(vulnerableApp, 'expected-findings.json'), 'utf8')) as {
        expected: ExpectedFinding[];
      }
    ).expected.filter((e) => implementedModules.includes(e.module));
    const foundRuleIds = new Set(report.findings.map((f) => f.ruleId));
    for (const entry of expected) {
      expect(foundRuleIds, `expected rule ${entry.ruleId} (${entry.module}) in scan output`).toContain(
        entry.ruleId,
      );
    }

    // With zero findings at or above the default threshold the exit code is 0.
    if (report.findings.every((f) => !['high', 'critical'].includes(f.severity))) {
      expect(status).toBe(0);
    }
  });

  it('scan clean-app --fail-on high exits 0 with zero high/critical findings', () => {
    const jsonRun = runCli(['scan', cleanApp, '--json']);
    const report = JSON.parse(jsonRun.stdout) as JsonReport;
    expect(report.summary.bySeverity.high ?? 0).toBe(0);
    expect(report.summary.bySeverity.critical ?? 0).toBe(0);

    const gated = runCli(['scan', cleanApp, '--fail-on', 'high']);
    expect(gated.status).toBe(0);
  });

  it('scan vulnerable-app --fail-on high exit code matches the presence of high/critical findings', () => {
    const jsonRun = runCli(['scan', vulnerableApp, '--json']);
    const report = JSON.parse(jsonRun.stdout) as JsonReport;
    const hasHighOrCritical = report.findings.some((f) =>
      ['high', 'critical'].includes(f.severity),
    );

    const gated = runCli(['scan', vulnerableApp, '--fail-on', 'high']);
    expect(gated.status).toBe(hasHighOrCritical ? 1 : 0);
    // Phase gate: once any module that seeds high findings is implemented,
    // this locks in the spec's "exit code 1" e2e requirement.
    if (implementedModules.length > 0) {
      expect(hasHighOrCritical).toBe(true);
    }
  });

  it('never prints the unmasked fake secret in any output format', () => {
    const humanRun = runCli(['scan', vulnerableApp]);
    const jsonRun = runCli(['scan', vulnerableApp, '--json']);
    expect(humanRun.stdout).not.toContain(FAKE_AWS_KEY);
    expect(humanRun.stderr).not.toContain(FAKE_AWS_KEY);
    expect(jsonRun.stdout).not.toContain(FAKE_AWS_KEY);
    expect(jsonRun.stderr).not.toContain(FAKE_AWS_KEY);
  });

  it('prints the package version with --version', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
      version: string;
    };
    const { status, stdout } = runCli(['--version']);
    expect(status).toBe(0);
    expect(stdout.trim()).toBe(pkg.version);
  });

  it('exits 2 with an error message for a nonexistent scan path', () => {
    const { status, stderr } = runCli(['scan', join(root, 'definitely-not-a-dir')]);
    expect(status).toBe(2);
    expect(stderr).toContain('not a directory');
  });
});
