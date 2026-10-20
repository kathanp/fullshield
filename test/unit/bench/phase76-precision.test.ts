import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { afterEach, describe, expect, it } from 'vitest';

import { precisionReviewText, reviewBlocked } from '../../../bench/review-cli.mjs';
import { renderPrecisionReport } from '../../../scripts/precision-report.mjs';
import { samplePerRule, type SampleFinding } from '../../../scripts/precision-sample.mjs';

const root = process.cwd();
const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'fs-p76-'));
  dirs.push(dir);
  return dir;
}

function findings(): SampleFinding[] {
  const rows: SampleFinding[] = [];
  for (let i = 0; i < 15; i += 1) {
    rows.push({
      id: `sqli-${String(i).padStart(2, '0')}`,
      ruleId: 'SAST-SQLI-001',
      file: 'src/query.js',
      line: 10,
      severity: 'high',
      message: 'sql',
      trace: [{ file: 'src/query.js', line: 1, note: 'request query' }],
      label: 'tp',
      reviewer: 'cursor',
      note: 'do not keep',
    });
  }
  for (let i = 0; i < 3; i += 1) {
    rows.push({
      id: `xss-${i}`,
      ruleId: 'SAST-XSS-001',
      file: 'src/view.js',
      line: 4,
      severity: 'medium',
      message: 'xss',
      trace: [],
    });
  }
  return rows;
}

function runSample(extra: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [join(root, 'scripts', 'precision-sample.mjs'), ...extra], {
    cwd: root,
    encoding: 'utf8',
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

describe('Phase 76 precision sampling', () => {
  it('samples the same rows for a fixed seed and a different set for another seed', () => {
    const pool = findings();
    const reversed = [...pool].reverse();
    const a = samplePerRule(pool, 10, 76).map((row) => row.id);
    const b = samplePerRule(reversed, 10, 76).map((row) => row.id);
    const c = samplePerRule(pool, 10, 77).map((row) => row.id);
    expect(a).toEqual(b);
    expect(a).not.toEqual(c);
    expect(a.filter((id) => id.startsWith('sqli-'))).toHaveLength(10);
    expect(a.filter((id) => id.startsWith('xss-'))).toHaveLength(3);
  });

  it('writes null label, reviewer, and note, and refuses an untouched app', () => {
    const dir = tempDir();
    const checkout = join(dir, 'app');
    mkdirSync(join(checkout, 'src'), { recursive: true });
    const lines = Array.from({ length: 20 }, (_, i) => `line-${i + 1}-token`);
    writeFileSync(join(checkout, 'src', 'query.js'), `${lines.join('\n')}\n`);
    const scanPath = join(dir, 'scan.json');
    writeFileSync(scanPath, JSON.stringify({ findings: findings() }));
    const out = join(dir, 'dvna.todo.json');
    const once = runSample([
      '--app',
      'dvna',
      '--per-rule',
      '10',
      '--seed',
      '76',
      '--from',
      scanPath,
      '--checkout',
      checkout,
      '--out',
      out,
    ]);
    expect(once.status).toBe(0);
    const twice = runSample([
      '--app',
      'dvna',
      '--per-rule',
      '10',
      '--seed',
      '76',
      '--from',
      scanPath,
      '--checkout',
      checkout,
      '--out',
      join(dir, 'again.todo.json'),
    ]);
    expect(twice.status).toBe(0);
    const doc = JSON.parse(readFileSync(out, 'utf8')) as {
      rows: Array<{ id: string; label: unknown; reviewer: unknown; note: unknown; snippet: string; trace: Array<{ note: string }> }>;
    };
    const again = JSON.parse(readFileSync(join(dir, 'again.todo.json'), 'utf8')) as { rows: Array<{ id: string }> };
    expect(doc.rows.map((row) => row.id)).toEqual(again.rows.map((row) => row.id));
    expect(doc.rows.length).toBeGreaterThan(0);
    for (const row of doc.rows) {
      expect(row.label).toBeNull();
      expect(row.reviewer).toBeNull();
      expect(row.note).toBeNull();
    }
    const sqli = doc.rows.find((row) => row.id.startsWith('sqli-'));
    expect(sqli?.snippet).toContain('line-5-token');
    expect(sqli?.snippet).toContain('line-15-token');
    expect(sqli?.snippet).not.toContain('line-4-token');
    expect(sqli?.trace[0]?.note).toBe('request query');

    const seen = runSample([
      '--app',
      'goof',
      '--per-rule',
      '10',
      '--seed',
      '76',
      '--from',
      scanPath,
      '--checkout',
      checkout,
      '--out',
      join(dir, 'goof.todo.json'),
    ]);
    expect(seen.status).toBe(0);

    const blocked = runSample([
      '--app',
      'mongection',
      '--per-rule',
      '10',
      '--seed',
      '76',
      '--from',
      scanPath,
      '--out',
      join(dir, 'untouched.todo.json'),
    ]);
    expect(blocked.status).not.toBe(0);
    expect(`${blocked.stderr}`).toMatch(/untouched/);
  });

  it('reports Wilson precision from human labels only', () => {
    const rows = [
      ...Array.from({ length: 8 }, () => ({ ruleId: 'SAST-SQLI-001', label: 'tp' })),
      ...Array.from({ length: 2 }, () => ({ ruleId: 'SAST-SQLI-001', label: 'fp' })),
      { ruleId: 'SAST-SQLI-001', label: 'unsure' },
      ...Array.from({ length: 6 }, () => ({ ruleId: 'SAST-SQLI-001', label: null, reviewer: null, note: null })),
      ...Array.from({ length: 2 }, () => ({ ruleId: 'SAST-XSS-001', label: 'tp' })),
      { ruleId: 'SAST-XSS-001', label: 'fp' },
      ...Array.from({ length: 4 }, () => ({ ruleId: 'SAST-CMDI-001', label: null })),
    ];
    const report = renderPrecisionReport(rows);
    expect(report).toContain('0.800');
    expect(report).toContain('[0.490, 0.943]');
    expect(report).toContain('insufficient sample');
    expect(report).toContain('0.667');
    expect(report).toContain('[0.208, 0.939]');
    expect(report).not.toContain('SAST-CMDI-001');
    const sqli = report.split('\n').find((line) => line.includes('SAST-SQLI-001'));
    expect(sqli).toBeDefined();
    expect(sqli).not.toContain('insufficient sample');

    const dir = tempDir();
    const input = join(dir, 'hand.todo.json');
    const out = join(dir, 'REPORT.md');
    writeFileSync(input, JSON.stringify({ rows }));
    const result = spawnSync(process.execPath, [join(root, 'scripts', 'precision-report.mjs'), input, '--out', out], {
      cwd: root,
      encoding: 'utf8',
    });
    expect(result.status).toBe(0);
    expect(readFileSync(out, 'utf8')).toBe(report);
  });

  it('refuses a todo file with zero labels', () => {
    const dir = tempDir();
    const input = join(dir, 'blank.todo.json');
    const out = join(dir, 'REPORT.md');
    writeFileSync(
      input,
      JSON.stringify({
        rows: [
          { ruleId: 'SAST-SQLI-001', label: null, reviewer: null, note: null },
          { ruleId: 'SAST-XSS-001', label: null, reviewer: null, note: null },
        ],
      }),
    );
    expect(() => renderPrecisionReport([{ ruleId: 'SAST-SQLI-001', label: null }])).toThrow(/zero labels/);
    const result = spawnSync(process.execPath, [join(root, 'scripts', 'precision-report.mjs'), input, '--out', out], {
      cwd: root,
      encoding: 'utf8',
    });
    expect(result.status).not.toBe(0);
    expect(`${result.stderr}`).toMatch(/zero labels/);
    expect(() => readFileSync(out, 'utf8')).toThrow();
  });

  it('shows the snippet and trace in the review CLI and stays closed without a TTY', () => {
    const text = precisionReviewText({
      ruleId: 'SAST-SQLI-001',
      file: 'src/query.js',
      line: 10,
      snippet: 'db.query(req.query.id)',
      trace: [{ file: 'src/query.js', line: 1, note: 'request query' }],
      label: null,
      reviewer: null,
      note: null,
    });
    expect(text).toContain('db.query(req.query.id)');
    expect(text).toContain('request query');
    expect(text).toMatch(/tp/);
    expect(text).toMatch(/fp/);
    expect(text).toMatch(/unsure/);
    expect(reviewBlocked({ CI: '1' }, true)).toMatch(/CI/);
    expect(reviewBlocked({ CURSOR_AGENT: '1' }, true)).toMatch(/agent/);
    expect(reviewBlocked({}, false)).toMatch(/TTY/);
    expect(reviewBlocked({}, true)).toBe('');
  });

  it('keeps the sampler and the precision directory out of the npm pack', () => {
    const listed = readFileSync(join(root, 'quality', 'pack-files.txt'), 'utf8');
    expect(listed).not.toContain('scripts/precision-sample.mjs');
    expect(listed).not.toContain('scripts/precision-report.mjs');
    expect(listed).not.toContain('bench/precision');
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { files?: string[] };
    const files = pkg.files ?? [];
    expect(files.some((name) => name === 'scripts' || name.startsWith('scripts/') || name === 'bench' || name.startsWith('bench/'))).toBe(
      false,
    );
  });
});
