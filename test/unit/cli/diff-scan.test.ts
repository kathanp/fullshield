import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { runDoctor } from '../../../src/cli/commands/doctor.js';
import { createProgram } from '../../../src/cli/program.js';
import { scan } from '../../../src/core/engine.js';
import {
  DIFF_FLAG,
  addedFails,
  diffScans,
  parseScanDocument,
  renderDiffText,
  type DiffFinding,
} from '../../../src/diff/index.js';

function finding(overrides: Partial<DiffFinding> & Pick<DiffFinding, 'ruleId' | 'severity'>): DiffFinding {
  return {
    id: `${overrides.ruleId}-${overrides.file ?? ''}-${overrides.line ?? 0}`,
    module: 'sast',
    title: overrides.ruleId,
    confidence: 'high',
    message: 'msg',
    remediation: 'fix',
    ...overrides,
  };
}

describe('diffScans', () => {
  it('splits unchanged, added, and removed by rule, file, line, and severity', () => {
    const keep = finding({ ruleId: 'SAST-SQLI-001', severity: 'high', file: 'src/a.js', line: 4 });
    const gone = finding({ ruleId: 'SAST-XSS-001', severity: 'medium', file: 'src/a.js', line: 9 });
    const fresh = finding({ ruleId: 'SAST-PATH-001', severity: 'high', file: 'src/b.js', line: 2 });
    const diff = diffScans([keep, gone], [keep, fresh]);
    expect(diff.unchanged.map((item) => item.ruleId)).toEqual(['SAST-SQLI-001']);
    expect(diff.added.map((item) => item.ruleId)).toEqual(['SAST-PATH-001']);
    expect(diff.removed.map((item) => item.ruleId)).toEqual(['SAST-XSS-001']);
  });

  it('treats a windows path and a posix path as the same file', () => {
    const before = finding({ ruleId: 'SAST-SQLI-001', severity: 'high', file: 'src\\a.js', line: 1 });
    const after = finding({ ruleId: 'SAST-SQLI-001', severity: 'high', file: 'src/a.js', line: 1 });
    const diff = diffScans([before], [after]);
    expect(diff.unchanged).toHaveLength(1);
    expect(diff.added).toHaveLength(0);
    expect(diff.removed).toHaveLength(0);
  });

  it('reports a line-only shift as a move', () => {
    const before = finding({ ruleId: 'SAST-SQLI-001', severity: 'high', file: 'src/a.js', line: 1 });
    const after = finding({ ruleId: 'SAST-SQLI-001', severity: 'high', file: 'src/a.js', line: 8 });
    const diff = diffScans([before], [after]);
    expect(diff.moved).toHaveLength(1);
    expect(diff.moved[0]?.before.line).toBe(1);
    expect(diff.moved[0]?.after.line).toBe(8);
    expect(diff.unchanged).toHaveLength(0);
    expect(diff.added).toHaveLength(0);
    expect(diff.removed).toHaveLength(0);
  });

  it('keeps two identical findings in one file distinct', () => {
    const first = finding({
      ruleId: 'SAST-SQLI-001',
      severity: 'high',
      file: 'src/a.js',
      line: 4,
      snippet: 'db.query(id)',
    });
    const second = finding({
      ruleId: 'SAST-SQLI-001',
      severity: 'high',
      file: 'src/a.js',
      line: 9,
      snippet: 'db.query(id)',
    });
    const same = diffScans([first, second], [first, second]);
    expect(same.unchanged).toHaveLength(2);
    expect(same.moved).toHaveLength(0);
    expect(same.added).toHaveLength(0);
    expect(same.removed).toHaveLength(0);

    const shifted = diffScans(
      [first, second],
      [{ ...first, line: 9 }, { ...second, line: 14 }],
    );
    expect(shifted.moved).toHaveLength(2);
    expect(shifted.unchanged).toHaveLength(0);
    expect(shifted.added).toHaveLength(0);
    expect(shifted.removed).toHaveLength(0);
  });

  it('pairs a single shared id as a move and leaves duplicate ids unmatched', () => {
    const before = finding({
      id: 'same',
      ruleId: 'SAST-SQLI-001',
      severity: 'high',
      file: 'src/a.js',
      line: 1,
      message: 'old text',
    });
    const after = finding({
      id: 'same',
      ruleId: 'SAST-SQLI-001',
      severity: 'high',
      file: 'src/a.js',
      line: 20,
      message: 'new text',
    });
    const moved = diffScans([before], [after]);
    expect(moved.moved).toEqual([{ before, after }]);
    expect(moved.added).toHaveLength(0);
    expect(moved.removed).toHaveLength(0);

    const extra = finding({ id: 'same', ruleId: 'SAST-XSS-001', severity: 'low', file: 'src/c.js', line: 3 });
    const ambiguous = diffScans([before], [after, extra]);
    expect(ambiguous.moved).toHaveLength(0);
    expect(ambiguous.added).toHaveLength(2);
    expect(ambiguous.removed).toHaveLength(1);
  });

  it('reads a findings object and a bare array', () => {
    const one = finding({ ruleId: 'SAST-SQLI-001', severity: 'high', file: 'src/a.js', line: 1 });
    expect(parseScanDocument(JSON.stringify({ findings: [one] }))).toEqual([one]);
    expect(parseScanDocument(JSON.stringify([one]))).toEqual([one]);
    expect(() => parseScanDocument('{"findings":{}}')).toThrow(/scan JSON/);
    expect(() => parseScanDocument('{"findings":[{"ruleId":"X","severity":"nope"}]}')).toThrow(/unknown severity/);
  });

  it('lists at most 20 added findings and does not fail on an AI finding', () => {
    const added = Array.from({ length: 21 }, (_, index) =>
      finding({ ruleId: 'SAST-SQLI-001', severity: 'info', file: 'src/a.js', line: index + 1 }),
    );
    const text = renderDiffText(diffScans([], added));
    expect(text).toContain('src/a.js:1');
    expect(text).toContain('src/a.js:20');
    expect(text).not.toContain('src/a.js:21');
    expect(text).toContain('1 more — use --json');
    const ai = finding({
      ruleId: 'SAST-SQLI-001',
      severity: 'high',
      file: 'src/ai.js',
      line: 1,
      source: 'ai',
    });
    expect(addedFails(diffScans([], [ai]), 'high')).toBe(false);
  });
});

describe('fullshield diff', () => {
  const dirs: string[] = [];

  afterEach(async () => {
    delete process.env[DIFF_FLAG];
    process.exitCode = undefined;
    for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
  });

  async function writePair(): Promise<{ dir: string; before: string; after: string }> {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-diff-'));
    dirs.push(dir);
    const before = join(dir, 'before.json');
    const after = join(dir, 'after.json');
    const kept = finding({ ruleId: 'SAST-XSS-001', severity: 'medium', file: 'src/a.js', line: 2 });
    const added = finding({ ruleId: 'SAST-SQLI-001', severity: 'high', file: 'src/b.js', line: 3 });
    await writeFile(before, JSON.stringify({ findings: [kept] }));
    await writeFile(after, JSON.stringify({ findings: [kept, added] }));
    return { dir, before, after };
  }

  it('refuses to run without the experimental flag', async () => {
    const { before, after } = await writePair();
    const err: string[] = [];
    const program = createProgram({ out: () => {}, err: (text) => err.push(text) });
    await program.parseAsync(['node', 'fullshield', 'diff', before, after]);
    expect(process.exitCode).toBe(2);
    expect(err.join('\n')).toContain('FS-E006');
    expect(err.join('\n')).toContain(DIFF_FLAG);
  });

  it('exits 1 when an added finding meets the default high threshold', async () => {
    const { before, after } = await writePair();
    const out: string[] = [];
    const program = createProgram({ out: (text) => out.push(text), err: () => {} });
    await program.parseAsync(['node', 'fullshield', 'diff', before, after, '--experimental-diff', '--json']);
    expect(process.exitCode).toBe(1);
    const parsed = JSON.parse(out.join('\n')) as { added: DiffFinding[]; unchanged: DiffFinding[] };
    expect(parsed.added).toHaveLength(1);
    expect(parsed.unchanged).toHaveLength(1);
  });

  it('exits 0 when the only added finding is below the threshold', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-diff-'));
    dirs.push(dir);
    const before = join(dir, 'before.json');
    const after = join(dir, 'after.json');
    const added = finding({ ruleId: 'CONFIG-SCRIPTS-001', severity: 'info', file: 'package.json', line: 1, module: 'config' });
    await writeFile(before, JSON.stringify({ findings: [] }));
    await writeFile(after, JSON.stringify({ findings: [added] }));
    const program = createProgram({ out: () => {}, err: () => {} });
    await program.parseAsync([
      'node',
      'fullshield',
      'diff',
      before,
      after,
      '--experimental-diff',
      '--json',
      '--fail-on',
      'high',
    ]);
    expect(process.exitCode).toBeUndefined();
  });

  it('writes the json diff and keeps the human summary on stdout', async () => {
    const { dir, before, after } = await writePair();
    const out: string[] = [];
    const program = createProgram({ out: (text) => out.push(text), err: () => {} });
    const dest = join(dir, 'diff.json');
    await program.parseAsync(['node', 'fullshield', 'diff', before, after, '--experimental-diff', '--out', dest]);
    expect(out.join('\n')).toContain('fullshield diff: unchanged 1, added 1, removed 0, moved 0');
    const parsed = JSON.parse(await readFile(dest, 'utf8')) as { added: DiffFinding[] };
    expect(parsed.added).toHaveLength(1);
  });

  it('treats five inserted blank lines as moves and exits 0', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-diff-blank-'));
    dirs.push(dir);
    const source = 'function handler(req) {\n  const id = req.query.id;\n  db.query(\'SELECT \' + id);\n}\n';
    await writeFile(join(dir, 'app.js'), source);
    const beforeScan = await scan({ cwd: dir, modules: ['sast'] });
    expect(beforeScan.findings.some((item) => item.ruleId === 'SAST-SQLI-001')).toBe(true);
    const before = join(dir, 'before.json');
    const after = join(dir, 'after.json');
    await writeFile(before, JSON.stringify({ findings: beforeScan.findings }));
    await writeFile(join(dir, 'app.js'), `\n\n\n\n\n${source}`);
    const afterScan = await scan({ cwd: dir, modules: ['sast'] });
    await writeFile(after, JSON.stringify({ findings: afterScan.findings }));
    const out: string[] = [];
    const program = createProgram({ out: (text) => out.push(text), err: () => {} });
    await program.parseAsync(['node', 'fullshield', 'diff', before, after, '--experimental-diff', '--json']);
    expect(process.exitCode ?? 0).toBe(0);
    const parsed = JSON.parse(out.join('\n')) as {
      unchanged: DiffFinding[];
      added: DiffFinding[];
      removed: DiffFinding[];
      moved: unknown[];
    };
    expect(parsed.added).toEqual([]);
    expect(parsed.removed).toEqual([]);
    expect(parsed.unchanged).toEqual([]);
    expect(parsed.moved.length).toBeGreaterThan(0);
  });

  it('doctor lists the diff flag when it is set', async () => {
    process.env[DIFF_FLAG] = '1';
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-diff-doctor-'));
    dirs.push(dir);
    const text = await runDoctor(dir);
    expect(text).toContain('FULLSHIELD_EXPERIMENTAL_DIFF');
  });
});
