import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const script = join(process.cwd(), 'scripts', 'promotion-batch2.mjs');
const fixture = join(process.cwd(), 'test', 'fixtures', 'promotion-batch2');

interface Row {
  flag: string;
  met: string;
  unmet: string;
  diff: string;
}

function rowsOf(summary: string): Row[] {
  return summary
    .split('\n')
    .filter((line) => line.startsWith('| `FULLSHIELD_EXPERIMENTAL_'))
    .map((line) => {
      const cells = line.split('|').map((cell) => cell.trim()).filter((cell) => cell !== '');
      return { flag: cells[0] ?? '', met: cells[1] ?? '', unmet: cells[2] ?? '', diff: cells[3] ?? '' };
    });
}

function run(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

describe('Phase 93 promotion evidence', () => {
  it('lists only flags visible in the tree and refuses to mark one stable', () => {
    const out = mkdtempSync(join(tmpdir(), 'fs93-'));
    try {
      const report = run(['--root', fixture, '--out', out]);
      expect(report.status).toBe(0);
      const summary = readFileSync(join(out, 'SUMMARY.md'), 'utf8');
      const visible = readFileSync(join(fixture, 'src', 'seen.ts'), 'utf8');
      const rows = rowsOf(summary);
      expect(rows.length).toBeGreaterThan(0);
      expect(summary).not.toContain('FULLSHIELD_EXPERIMENTAL_NOT_A_BATCH_FLAG');
      for (const row of rows) {
        const name = row.flag.replaceAll('`', '');
        expect(row.met.toLowerCase()).not.toContain('promoted');
        expect(row.unmet.toLowerCase()).not.toContain('promoted');
        expect(row.diff).toBe('EMPTY');
        if (row.unmet.includes('not in this tree')) {
          expect(visible).not.toContain(name);
        } else {
          expect(visible).toContain(name);
        }
        const detail = readFileSync(join(out, `${name}.md`), 'utf8');
        expect(detail).toContain('tuning-app key diff');
        expect(detail).toContain('crash count');
        expect(detail).toContain('default-scan-diff if promoted');
        expect(detail).toContain('criteria not met');
        expect(detail).not.toMatch(/crash count[^\n]*\d/);
      }
      const validation = rows.find((row) => row.flag.includes('VALIDATION'));
      expect(validation?.unmet).not.toContain('not in this tree');
      const routes = rows.find((row) => row.flag.includes('_ROUTES'));
      expect(routes?.unmet).toContain('not in this tree');

      const refused = run(['--root', fixture, '--out', out, '--promote']);
      expect(refused.status).not.toBe(0);
      expect(readFileSync(join(out, 'SUMMARY.md'), 'utf8')).toBe(summary);
      expect(`${refused.stdout}\n${summary}`).not.toMatch(/\|\s*promoted\s*\|/i);
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  });
});
