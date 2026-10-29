import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';
import { formatCliError } from '../../../src/cli/errors.js';
import { DEFAULT_CONFIG } from '../../../src/core/config.js';
import type { ScanResult } from '../../../src/core/engine.js';
import { makeFindingId, summarize, type Finding } from '../../../src/core/finding.js';
import { applyOneSafeFix } from '../../../src/fixer/one-finding.js';
import { proposeFix } from '../../../src/fixer/patches.js';
import {
  localRuleFindings,
  parseLocalRules,
  reachabilityCounts,
  taintEdgeLine,
  withExtraFindings,
} from '../../../src/modules/sast/parity.js';
import { renderHtmlReport } from '../../../src/reporters/html.js';

const dirs: string[] = [];

afterEach(async () => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_SAST_PARITY;
  process.exitCode = undefined;
  for (const dir of dirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fullshield-parity-'));
  dirs.push(dir);
  return dir;
}

function finding(partial: Partial<Finding>): Finding {
  return {
    id: makeFindingId(partial.ruleId ?? 'R', partial.file, partial.snippet),
    ruleId: 'R',
    module: 'sast',
    title: 't',
    severity: 'high',
    confidence: 'high',
    message: 'm',
    remediation: 'fix it',
    ...partial,
  };
}

function result(findings: Finding[]): ScanResult {
  return {
    findings,
    summary: summarize(findings),
    metadata: {
      version: '3.1.2',
      startedAt: '2026-10-29T00:00:00.000Z',
      durationMs: 1,
      cwd: '/tmp/app',
      filesScanned: 1,
      modulesRequested: ['sast'],
      modulesRun: ['sast'],
    },
    config: structuredClone(DEFAULT_CONFIG),
  };
}

describe('phase 565 sast parity', () => {
  it('counts severity and reachability and refuses the option before a scan when the flag is off', async () => {
    const text = reachabilityCounts([
      finding({ severity: 'high', reachability: 'reachable' }),
      finding({ severity: 'high', reachability: 'reachable' }),
      finding({ severity: 'critical' }),
      finding({ severity: 'low', reachability: 'not-imported' }),
    ]);
    expect(text).not.toMatch(/grade|score|certification/i);
    expect(JSON.parse(text)).toEqual({
      bySeverityReachability: [
        { severity: 'critical', reachability: 'unspecified', count: 1 },
        { severity: 'high', reachability: 'reachable', count: 2 },
        { severity: 'low', reachability: 'not-imported', count: 1 },
      ],
    });
    const err: string[] = [];
    let scanned = false;
    const program = createProgram({
      out: () => undefined,
      err: (line) => err.push(line),
      scan: () => {
        scanned = true;
        return Promise.resolve(result([]));
      },
    });
    await program.parseAsync(['node', 'fullshield', 'scan', '--counts']);
    expect(scanned).toBe(false);
    expect(err.join('\n')).toMatch(/FS-E024/);
    expect(formatCliError(new Error('scan --counts requires FULLSHIELD_EXPERIMENTAL_SAST_PARITY'))).toMatch(/FS-E024/);
  });

  it('reads a local rules file only when the flag is on and does not walk node_modules', async () => {
    const cwd = await tempDir();
    await writeFile(join(cwd, 'app.js'), 'const token = "hello world";\nsafe();\n', 'utf8');
    await mkdir(join(cwd, 'node_modules', 'left-pad'), { recursive: true });
    await writeFile(join(cwd, 'node_modules', 'left-pad', 'index.js'), 'hello world', 'utf8');
    const yaml = [
      '- schema: 1',
      '  pattern: "hello world"',
      '  message: "literal marker"',
      '  severity: high',
      '- schema: 1',
      '  pattern: missing-marker',
      '  message: "no hit"',
      '  severity: low',
    ].join('\n');
    await writeFile(join(cwd, 'fullshield.rules.yml'), yaml, 'utf8');
    expect(await localRuleFindings(cwd)).toEqual([]);
    process.env.FULLSHIELD_EXPERIMENTAL_SAST_PARITY = '1';
    const hits = await localRuleFindings(cwd);
    expect(hits.map((row) => `${row.ruleId}:${row.file}:${row.line}`)).toEqual(['YAML-RULE-001:app.js:1']);
    expect(hits[0]?.message).toBe('literal marker');
    expect(await localRuleFindings(await tempDir())).toEqual([]);
    await writeFile(join(cwd, 'fullshield.rules.yml'), '\n', 'utf8');
    expect(await localRuleFindings(cwd)).toEqual([]);
    await writeFile(join(cwd, 'fullshield.rules.yml'), '- schema: 2\n  pattern: a\n  message: b\n  severity: low\n', 'utf8');
    await expect(localRuleFindings(cwd)).rejects.toThrow(/cannot read local rules/);
    expect(() => parseLocalRules('- schema: 1\n  pattern: ""\n  message: b\n  severity: low\n')).toThrow(/rule shape/);
    expect(() => parseLocalRules('- schema: 1\n  pattern: a\n  message: b\n  severity: critical\n')).toThrow(/severity/);
    expect(() => parseLocalRules('schema: 1\n')).toThrow(/rule shape/);
    expect(() => parseLocalRules('- schema: 1\n  schema: 1\n  pattern: a\n  message: b\n  severity: low\n')).toThrow(/duplicate/);
    expect(() => parseLocalRules('- schema: 1\n  pattern: "say \\"hi\\""\n  message: b\n  severity: medium\n')).not.toThrow();
    const source = await readFile(join(import.meta.dirname, '../../../src/modules/sast/parity.ts'), 'utf8');
    expect(source).not.toContain('child_process');
    expect(source).not.toContain('fetch(');
    const same = result([finding({})]);
    expect(withExtraFindings(same, [])).toBe(same);
    const added = withExtraFindings(result([]), [finding({ severity: 'low', ruleId: 'YAML-RULE-001' })]);
    expect(added.summary.total).toBe(1);
    expect(added.findings[0]?.ruleId).toBe('YAML-RULE-001');
    await mkdir(join(cwd, 'src'), { recursive: true });
    await writeFile(join(cwd, 'src', 'nested.js'), 'hello world\n', 'utf8');
    await symlink('app.js', join(cwd, 'link.js'));
    await writeFile(join(cwd, 'fullshield.rules.yml'), yaml, 'utf8');
    const again = await localRuleFindings(cwd);
    expect(again.map((row) => row.file).sort()).toEqual(['app.js', 'src/nested.js']);
    await rm(join(cwd, 'fullshield.rules.yml'));
    await mkdir(join(cwd, 'fullshield.rules.yml'));
    await expect(localRuleFindings(cwd)).rejects.toThrow(/unreadable/);
    expect(parseLocalRules('')).toEqual([]);
    expect(() => parseLocalRules('- schema: 1\n  pattern:\n  message: b\n  severity: low\n')).toThrow(/empty value/);
    expect(() => parseLocalRules('- schema: 1\n  pattern: "open\n  message: b\n  severity: low\n')).toThrow(/open quote/);
    expect(() => parseLocalRules('- schema: 1\n  pattern: a:b\n  message: b\n  severity: low\n')).toThrow(/unsupported/);
    expect(() => parseLocalRules('- schema: 1\n  pattern: "bad \\x"\n  message: b\n  severity: low\n')).toThrow(/bad escape/);
  });

  it('draws a taint edge only when the trace already has a source and a sink', () => {
    const both = finding({
      trace: [
        { file: 'src/in.js', line: 2, note: 'source' },
        { file: 'src/out.js', line: 9, note: 'sink' },
      ],
    });
    const html = renderHtmlReport(result([both]), true);
    expect(html).toContain('<p class="taint">source src/in.js:2 sink src/out.js:9</p>');
    const off = renderHtmlReport(result([both]), false);
    expect(off).not.toContain('taint');
    expect(off).toBe(renderHtmlReport(result([both])));
    const one = finding({ trace: [{ file: 'src/in.js', line: 2, note: 'only' }] });
    expect(taintEdgeLine(one)).toBeUndefined();
    expect(renderHtmlReport(result([one]), true)).not.toContain('taint');
    expect(taintEdgeLine(finding({ trace: [{ file: 'src/in.js', note: 'no line' }, { file: 'src/out.js', line: 1, note: 'sink' }] }))).toBeUndefined();
  });

  it('writes one safe fix and leaves every other file untouched', async () => {
    const cwd = await tempDir();
    const source = 'const app = express();\napp.use(express.json());\n';
    await writeFile(join(cwd, 'app.js'), source, 'utf8');
    await writeFile(join(cwd, 'other.js'), 'leave me\n', 'utf8');
    const match = finding({
      ruleId: 'CONFIG-BODYLIMIT-001',
      file: 'app.js',
      line: 2,
      snippet: 'app.use(express.json());',
    });
    expect(proposeFix(match, source)?.safe).toBe(true);
    process.env.FULLSHIELD_EXPERIMENTAL_SAST_PARITY = '1';
    await expect(applyOneSafeFix({ cwd, selector: 'nope', force: true, findings: [match] })).rejects.toThrow(/selector/);
    await expect(applyOneSafeFix({ cwd, selector: 'R:../app.js:1', force: true, findings: [match] })).rejects.toThrow(/selector/);
    await expect(applyOneSafeFix({ cwd, selector: 'R:/tmp/app.js:1', force: true, findings: [match] })).rejects.toThrow(/selector/);
    await expect(applyOneSafeFix({ cwd, selector: 'R:app.js:0', force: true, findings: [match] })).rejects.toThrow(/selector/);
    await expect(applyOneSafeFix({
      cwd,
      selector: 'CONFIG-BODYLIMIT-001:app.js:2',
      force: true,
      findings: [match, match],
    })).rejects.toThrow(/did not match one/);
    expect(await readFile(join(cwd, 'app.js'), 'utf8')).toBe(source);
    await expect(applyOneSafeFix({
      cwd,
      selector: 'CONFIG-BODYLIMIT-001:app.js:2',
      force: false,
      findings: [match],
    })).rejects.toThrow(/git repository/);
    expect(await readFile(join(cwd, 'app.js'), 'utf8')).toBe(source);
    const wrote = await applyOneSafeFix({
      cwd,
      selector: 'CONFIG-BODYLIMIT-001:app.js:2',
      force: true,
      findings: [match],
    });
    expect(wrote.file).toBe('app.js');
    expect(await readFile(join(cwd, 'app.js'), 'utf8')).toContain("limit: '100kb'");
    expect(await readFile(join(cwd, 'other.js'), 'utf8')).toBe('leave me\n');
    const unsafe = finding({
      ruleId: 'CONFIG-BODYLIMIT-001',
      file: 'other.js',
      line: 1,
      fix: { kind: 'code-patch', safe: false, diff: '--- a\n+++ b\n+hacked\n' },
    });
    await expect(applyOneSafeFix({
      cwd,
      selector: 'CONFIG-BODYLIMIT-001:other.js:1',
      force: true,
      findings: [unsafe],
    })).rejects.toThrow(/no safe fix/);
    expect(await readFile(join(cwd, 'other.js'), 'utf8')).toBe('leave me\n');
    const fixer = await readFile(join(import.meta.dirname, '../../../src/fixer/one-finding.ts'), 'utf8');
    expect(fixer).not.toContain('child_process');
    expect(fixer).not.toContain('runProjectTests');
    const err: string[] = [];
    delete process.env.FULLSHIELD_EXPERIMENTAL_SAST_PARITY;
    const program = createProgram({ out: () => undefined, err: (line) => err.push(line) });
    await program.parseAsync(['node', 'fullshield', 'fix', '--finding', 'R:a.js:1']);
    expect(err.join('\n')).toMatch(/FS-E024/);
  });

  it('refuses a dirty git tree unless force is set', async () => {
    const cwd = await tempDir();
    const source = 'const app = express();\napp.use(express.json());\n';
    await writeFile(join(cwd, 'app.js'), source, 'utf8');
    const git = (...args: string[]): void => {
      execFileSync('git', ['-c', 'user.email=dev@example.com', '-c', 'user.name=dev', ...args], { cwd });
    };
    git('init');
    git('add', 'app.js');
    git('commit', '-m', 'init');
    await writeFile(join(cwd, 'dirty.txt'), 'x\n', 'utf8');
    const match = finding({ ruleId: 'CONFIG-BODYLIMIT-001', file: 'app.js', line: 2 });
    process.env.FULLSHIELD_EXPERIMENTAL_SAST_PARITY = '1';
    await expect(applyOneSafeFix({
      cwd,
      selector: 'CONFIG-BODYLIMIT-001:app.js:2',
      force: false,
      findings: [match],
    })).rejects.toThrow(/clean git tree/);
    expect(await readFile(join(cwd, 'app.js'), 'utf8')).toBe(source);
  });
});
