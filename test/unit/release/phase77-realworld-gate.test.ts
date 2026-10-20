import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import { runDiff } from '../../../scripts/realworld-diff.mjs';
import {
  buildSnapshot,
  findingKey,
  gateExitCode,
  materializeRepo,
  readApprovedKeys,
} from '../../../scripts/realworld-lib.mjs';
import { runSnapshot } from '../../../scripts/realworld-snapshot.mjs';

const fixtureRepo = resolve(process.cwd(), 'test/fixtures/phase77/repo');
const approvedInRepo = join(process.cwd(), 'bench/snapshots/realworld-approved.txt');
const temps: string[] = [];

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'phase77-'));
  temps.push(dir);
  return dir;
}

async function scanFindings(dir: string) {
  const result = await scan({ cwd: dir, offline: true });
  return result.findings;
}

afterEach(() => {
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('Phase 77 real-world precision gate', () => {
  it('flags one added key from the fixture rule change and passes once that key is approved', async () => {
    const dir = tempDir();
    const registry = join(dir, 'realworld.json');
    const snapshot = join(dir, 'realworld.json.snap');
    const approved = join(dir, 'realworld-approved.txt');
    const cache = join(dir, 'cache');
    writeFileSync(
      registry,
      JSON.stringify({ repos: [{ name: 'fixture-app', path: fixtureRepo }] }),
    );

    const findings = await scanFindings(fixtureRepo);
    const keys = findings.map((finding) => findingKey(finding)).sort();
    const added = keys.filter(
      (key) => key.startsWith('SAST-EVAL-001\t') && key.includes('src/added.js'),
    );
    expect(added).toHaveLength(1);
    expect(keys.some((key) => key.startsWith('SAST-EVAL-001\t') && key.includes('literal.js'))).toBe(
      false,
    );

    const frozen = keys.filter((key) => key !== added[0]);
    writeFileSync(
      snapshot,
      JSON.stringify(buildSnapshot({ 'fixture-app': { sha: null, keys: frozen } })),
    );

    let out = '';
    const blocked = await runDiff(
      ['--registry', registry, '--snapshot', snapshot, '--approved', approved, '--cache', cache],
      {
        scanFindings,
        stdout: (chunk: string) => {
          out += chunk;
        },
      },
    );
    expect(blocked).toBe(1);
    expect(out).toContain('fixture-app');
    expect(out).toContain(`+ ${added[0]}`);
    const addedLines = out.split('\n').filter((line) => line.startsWith('+ '));
    expect(addedLines).toEqual([`+ ${added[0]}`]);

    writeFileSync(approved, `${added[0]}\n`);
    const before = readFileSync(approved);
    const stamp = statSync(approved).mtimeMs;
    let approvedOut = '';
    const allowed = await runDiff(
      ['--registry', registry, '--snapshot', snapshot, '--approved', approved, '--cache', cache],
      {
        scanFindings,
        stdout: (chunk: string) => {
          approvedOut += chunk;
        },
      },
    );
    expect(allowed).toBe(0);
    expect(approvedOut).toContain(`+ ${added[0]}`);
    expect(readFileSync(approved)).toEqual(before);
    expect(statSync(approved).mtimeMs).toBe(stamp);
  });

  it('does not fail when keys are only removed', async () => {
    const dir = tempDir();
    const registry = join(dir, 'realworld.json');
    const snapshot = join(dir, 'snap.json');
    const approved = join(dir, 'approved.txt');
    writeFileSync(registry, JSON.stringify({ repos: [{ name: 'fixture-app', path: fixtureRepo }] }));
    const findings = await scanFindings(fixtureRepo);
    const keys = findings.map((finding) => findingKey(finding));
    const extra = 'SAST-EVAL-001\tsrc/gone.js\t1\thigh';
    writeFileSync(
      snapshot,
      JSON.stringify(buildSnapshot({ 'fixture-app': { sha: null, keys: [...keys, extra] } })),
    );
    let out = '';
    const code = await runDiff(
      ['--registry', registry, '--snapshot', snapshot, '--approved', approved, '--cache', join(dir, 'cache')],
      {
        scanFindings,
        stdout: (chunk: string) => {
          out += chunk;
        },
      },
    );
    expect(code).toBe(0);
    expect(out).toContain(`- ${extra}`);
    expect(out.includes('+ ')).toBe(false);
  });

  it('exits 1 unless every added key is listed', () => {
    const one = 'SAST-EVAL-001\tsrc/added.js\t2\thigh';
    const other = 'SAST-EVAL-001\tsrc/added.js\t9\thigh';
    expect(gateExitCode([one], new Set())).toBe(1);
    expect(gateExitCode([one], new Set([one]))).toBe(0);
    expect(gateExitCode([one, other], new Set([one]))).toBe(1);
    expect(gateExitCode([], new Set())).toBe(0);
    expect(gateExitCode([one], new Set(['SAST-EVAL-001\tsrc/added.js\t2\tlow']))).toBe(1);
  });

  it('reads an approved list and does not create a missing one', () => {
    const dir = tempDir();
    const missing = join(dir, 'realworld-approved.txt');
    expect(readApprovedKeys(missing)).toEqual(new Set());
    expect(existsSync(missing)).toBe(false);
    const present = join(dir, 'listed.txt');
    writeFileSync(present, `# note\n\nSAST-EVAL-001\tsrc/added.js\t2\thigh\n`);
    expect(readApprovedKeys(present)).toEqual(new Set(['SAST-EVAL-001\tsrc/added.js\t2\thigh']));
    expect(readFileSync(present, 'utf8')).toContain('# note');
  });

  it('only reads realworld-approved.txt', () => {
    const writeApis = [
      'writeFileSync',
      'writeFile',
      'appendFile',
      'appendFileSync',
      'createWriteStream',
      'truncateSync',
      'rmSync',
      'unlinkSync',
      'copyFileSync',
      'renameSync',
      'openSync',
    ];
    const diff = readFileSync(join(process.cwd(), 'scripts/realworld-diff.mjs'), 'utf8');
    const lib = readFileSync(join(process.cwd(), 'scripts/realworld-lib.mjs'), 'utf8');
    const snapshot = readFileSync(join(process.cwd(), 'scripts/realworld-snapshot.mjs'), 'utf8');
    expect(snapshot.includes('realworld-approved.txt')).toBe(false);
    expect(diff.includes('readApprovedKeys')).toBe(true);
    for (const text of [diff, lib, snapshot]) {
      for (const line of text.split('\n')) {
        const lowered = line.toLowerCase();
        if (!lowered.includes('approved')) continue;
        for (const api of writeApis) {
          expect(line.includes(api)).toBe(false);
        }
      }
    }
    expect(existsSync(approvedInRepo)).toBe(false);
  });

  it('uses a local fixture path and does not clone or install it', async () => {
    const calls: string[][] = [];
    const resolved = await materializeRepo(
      { name: 'fixture-app', path: fixtureRepo },
      tempDir(),
      {
        spawn: () => {
          throw new Error('git should not run for a fixture path');
        },
      },
    );
    expect(resolved).toBe(fixtureRepo);

    const dir = tempDir();
    const registry = join(dir, 'realworld.json');
    const snapshot = join(dir, 'snap.json');
    const outFile = join(dir, 'out.json');
    writeFileSync(registry, JSON.stringify({ repos: [{ name: 'fixture-app', path: fixtureRepo }] }));
    await runSnapshot(['--registry', registry, '--out', outFile, '--cache', join(dir, 'cache')], {
      scanFindings,
      spawn: (_cmd: string, args: string[]) => {
        calls.push(args);
        return { status: 0, stdout: '', stderr: '' };
      },
    });
    expect(calls).toEqual([]);
    const written = JSON.parse(readFileSync(outFile, 'utf8')) as {
      repos: Record<string, { keys: string[] }>;
    };
    expect(written.repos['fixture-app']?.keys.some((key) => key.includes('src/added.js'))).toBe(true);
    expect(existsSync(approvedInRepo)).toBe(false);
  });

  it('clones with git fetch and checkout and does not execute the repo', async () => {
    const dir = tempDir();
    const calls: { cmd: string; args: string[]; cwd?: string }[] = [];
    await materializeRepo(
      {
        name: 'express',
        repo: 'https://github.com/expressjs/express.git',
        sha: 'a419aa7350389a275ab45fde2e849ed1f02449ef',
      },
      dir,
      {
        spawn: (cmd: string, args: string[], opts?: { cwd?: string }) => {
          calls.push({ cmd, args, cwd: opts?.cwd });
          return { status: 0, stdout: '', stderr: '' };
        },
      },
    );
    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) {
      expect(call.cmd).toBe('git');
      expect(call.args.join(' ')).not.toMatch(/\bnpm\b|\bnode\b|\bpnpm\b|\byarn\b/);
      expect(call.args.join(' ')).toContain('core.hooksPath');
      expect(call.args.join(' ')).toContain('core.attributesFile');
    }
    const flat = calls.map((call) => call.args.join(' ')).join('\n');
    expect(flat).toContain('fetch');
    expect(flat).toContain('--depth');
    expect(flat).toContain('a419aa7350389a275ab45fde2e849ed1f02449ef');
    expect(flat).toContain('checkout');
    expect(flat).toContain('--detach');
    expect(calls.some((call) => call.cwd === fixtureRepo)).toBe(false);
  });

  it('scans through the fullshield CLI and does not run the fixture as a program', async () => {
    const dir = tempDir();
    const registry = join(dir, 'realworld.json');
    const snapshot = join(dir, 'snap.json');
    const approved = join(dir, 'approved.txt');
    writeFileSync(registry, JSON.stringify({ repos: [{ name: 'fixture-app', path: fixtureRepo }] }));
    const findings = await scanFindings(fixtureRepo);
    writeFileSync(
      snapshot,
      JSON.stringify(
        buildSnapshot({
          'fixture-app': { sha: null, keys: findings.map((finding) => findingKey(finding)) },
        }),
      ),
    );
    writeFileSync(join(dir, 'cli.js'), '// scanner stand-in; the test spawn mock does not execute it\n');
    const spawns: { cmd: string; args: string[]; cwd?: string }[] = [];
    const code = await runDiff(
      ['--registry', registry, '--snapshot', snapshot, '--approved', approved, '--cache', join(dir, 'cache'), '--cli', join(dir, 'cli.js')],
      {
        stdout: () => {},
        spawn: (cmd: string, args: string[], opts?: { cwd?: string }) => {
          spawns.push({ cmd, args, cwd: opts?.cwd });
          return {
            status: 0,
            stdout: JSON.stringify({ findings: [] }),
            stderr: '',
          };
        },
      },
    );
    expect(spawns).toHaveLength(1);
    expect(spawns[0]?.cmd).toBe(process.execPath);
    expect(spawns[0]?.args.slice(1, 3)).toEqual(['scan', fixtureRepo]);
    expect(spawns[0]?.args).toContain('--json');
    expect(spawns[0]?.args).toContain('--offline');
    expect(spawns[0]?.cwd).toBe(process.cwd());
    expect(code).toBe(0);
  });

  it('adds a next-only CI job cached by the realworld pin file', () => {
    const ci = readFileSync(join(process.cwd(), '.github/workflows/ci.yml'), 'utf8');
    const at = ci.indexOf('realworld-precision:');
    expect(at).toBeGreaterThan(-1);
    const job = ci.slice(at);
    expect(job).toContain("if: github.event_name == 'push' && github.ref == 'refs/heads/next'");
    expect(job).toContain('runs-on: ubuntu-24.04');
    expect(job).toContain('timeout-minutes: 30');
    expect(job).toContain('node-version: 24');
    expect(job).toContain('actions/cache@5a3ec84eff668545956fd18022155c47e93e2684');
    expect(job).toContain('path: bench/.cache/realworld');
    expect(job).toContain("key: realworld-${{ hashFiles('bench/realworld.json') }}");
    expect(job).toContain('node scripts/realworld-diff.mjs');
    expect(job.includes('strategy:')).toBe(false);
    expect(job).not.toMatch(/uses:\s+\S+@v\d/);
    const matrix = ci.slice(0, at);
    expect(matrix).not.toContain('realworld-precision');
  });
});
