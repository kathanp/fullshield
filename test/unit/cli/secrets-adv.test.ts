import { execFileSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_SECRETS_ADV';
const GITHUB_TOKEN = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
const AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';

let savedExitCode: typeof process.exitCode;
const dirs: string[] = [];

beforeEach(() => {
  savedExitCode = process.exitCode;
  process.exitCode = undefined;
  delete process.env[FLAG];
});

afterEach(async () => {
  process.exitCode = savedExitCode;
  delete process.env[FLAG];
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) await rm(d, { recursive: true, force: true });
});

function git(cwd: string, ...args: string[]): void {
  execFileSync('git', ['-C', cwd, ...args], { stdio: 'ignore' });
}

async function runCli(args: string[]): Promise<{ out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const program = createProgram({
    out: (text) => out.push(text),
    err: (text) => err.push(text),
  });
  await program.parseAsync(['node', 'fullshield', ...args]);
  return { out: out.join('\n'), err: err.join('\n') };
}

describe('Phase 30 CLI flags', () => {
  it('registers history, bundle, verify-secrets, ownership, and experimental flags on scan', () => {
    const program = createProgram();
    const scan = program.commands.find((c) => c.name() === 'scan');
    expect(scan).toBeDefined();
    const longs = scan!.options.map((o) => o.long);
    expect(longs).toContain('--experimental-secrets-adv');
    expect(longs).toContain('--history');
    expect(longs).toContain('--bundle');
    expect(longs).toContain('--verify-secrets');
    expect(longs).toContain('--i-own-these-credentials');
  });

  it('CLI flags do nothing useful without FULLSHIELD_EXPERIMENTAL_SECRETS_ADV', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-cli-hist-'));
    dirs.push(cwd);
    git(cwd, 'init', '--quiet');
    git(cwd, 'config', 'user.email', 'test@example.com');
    git(cwd, 'config', 'user.name', 'Test');
    git(cwd, 'config', 'commit.gpgsign', 'false');
    await writeFile(join(cwd, 'app.js'), `const k = "${AWS_KEY}";\n`);
    git(cwd, 'add', 'app.js');
    git(cwd, 'commit', '-m', 'add');
    await writeFile(join(cwd, 'app.js'), 'const k = "rotated";\n');
    git(cwd, 'add', 'app.js');
    git(cwd, 'commit', '-m', 'remove');

    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const { out } = await runCli([
      'scan',
      cwd,
      '--json',
      '--modules',
      'secrets',
      '--history',
      '--verify-secrets',
      '--i-own-these-credentials',
    ]);
    const parsed = JSON.parse(out) as { findings: Array<{ ruleId: string; stillAtHead?: boolean }> };
    expect(parsed.findings.filter((f) => f.ruleId === 'SECRET-AWS-001')).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('live verification is impossible without both --verify-secrets and --i-own-these-credentials', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-cli-ver-'));
    dirs.push(cwd);
    git(cwd, 'init', '--quiet');
    git(cwd, 'config', 'user.email', 'test@example.com');
    git(cwd, 'config', 'user.name', 'Test');
    git(cwd, 'config', 'commit.gpgsign', 'false');
    await writeFile(join(cwd, 'app.js'), `const t = "${GITHUB_TOKEN}";\n`);
    git(cwd, 'add', 'app.js');
    git(cwd, 'commit', '-m', 'key');

    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const { out: a } = await runCli([
      'scan',
      cwd,
      '--json',
      '--modules',
      'secrets',
      '--experimental-secrets-adv',
      '--verify-secrets',
    ]);
    expect(fetchMock).not.toHaveBeenCalled();
    const parsedA = JSON.parse(a) as { findings: Array<{ verification?: string }> };
    expect(parsedA.findings.every((f) => f.verification === undefined)).toBe(true);

    const { out: b } = await runCli([
      'scan',
      cwd,
      '--json',
      '--modules',
      'secrets',
      '--experimental-secrets-adv',
      '--i-own-these-credentials',
    ]);
    expect(fetchMock).not.toHaveBeenCalled();
    const parsedB = JSON.parse(b) as { findings: Array<{ verification?: string }> };
    expect(parsedB.findings.every((f) => f.verification === undefined)).toBe(true);
  });
});
