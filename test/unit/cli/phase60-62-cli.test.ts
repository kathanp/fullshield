import { execFileSync } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';

const dirs: string[] = [];

async function runCli(args: string[]): Promise<{ out: string; err: string; code: number | undefined }> {
  const out: string[] = [];
  const err: string[] = [];
  const program = createProgram({
    out: (text) => out.push(text),
    err: (text) => err.push(text),
  });
  const before = process.exitCode;
  process.exitCode = undefined;
  await program.parseAsync(['node', 'fullshield', ...args]);
  const code = process.exitCode === undefined ? 0 : Number(process.exitCode);
  process.exitCode = before;
  return { out: out.join('\n'), err: err.join('\n'), code };
}

describe('phase 60 and 62 CLI', () => {
  afterEach(async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_EXPLAIN;
    delete process.env.FULLSHIELD_EXPERIMENTAL_DEPS_DIFF;
    delete process.env.FULLSHIELD_EXPERIMENTAL_REACH_EVIDENCE;
    delete process.env.FULLSHIELD_EXPERIMENTAL_LOCKFILES;
    delete process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY;
    await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('refuses explain and deps-diff without their flags', async () => {
    const explain = await runCli(['explain', 'abcdef']);
    expect(explain.err).toContain('FS-E007');
    expect(explain.code).toBe(2);
    const diff = await runCli(['deps-diff', 'HEAD']);
    expect(diff.err).toContain('FS-E008');
    expect(diff.code).toBe(2);
  });

  it('explains one finding from a scan file and diffs a lockfile', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-cli-batch-'));
    dirs.push(dir);
    const scanFile = join(dir, 'scan.json');
    await writeFile(
      scanFile,
      JSON.stringify({
        findings: [
          {
            id: 'abcdef123456',
            ruleId: 'SAST-SQLI-001',
            module: 'sast',
            title: 'SQL injection',
            severity: 'high',
            confidence: 'high',
            message: 'tainted',
            remediation: 'parameterize',
          },
        ],
      }),
    );
    process.env.FULLSHIELD_EXPERIMENTAL_EXPLAIN = '1';
    const explained = await runCli(['explain', 'abcdef', '--from', scanFile]);
    expect(explained.err).toBe('');
    expect(explained.out).toContain('SAST-SQLI-001');

    const lock = JSON.stringify({
      name: 'app',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { left: '1.0.0' } },
        'node_modules/left': { version: '1.0.0' },
      },
    });
    execFileSync('git', ['init'], { cwd: dir });
    execFileSync('git', ['config', 'user.email', 'cli@test.local'], { cwd: dir });
    execFileSync('git', ['config', 'user.name', 'CLI Test'], { cwd: dir });
    await writeFile(join(dir, 'package-lock.json'), lock);
    execFileSync('git', ['add', 'package-lock.json'], { cwd: dir });
    execFileSync('git', ['commit', '-m', 'lock'], { cwd: dir });
    process.env.FULLSHIELD_EXPERIMENTAL_DEPS_DIFF = '1';
    const diffed = await runCli(['deps-diff', 'HEAD', dir, '--offline', '--json']);
    expect(diffed.code).not.toBe(2);
    expect(diffed.out).toContain('"changes"');
  });

  it('accepts the new scan flags on clean-app', async () => {
    const clean = join(process.cwd(), 'test', 'fixtures', 'clean-app');
    const result = await runCli([
      'scan',
      clean,
      '--json',
      '--offline-safe',
      '--experimental-reach-evidence',
      '--experimental-lockfiles',
      '--experimental-supply',
    ]);
    expect(result.err).toBe('');
    expect(result.out).toContain('"findings"');
  });
});
