import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = join(process.cwd());

function text(path: string): string {
  return readFileSync(join(root, path), 'utf8');
}

function rows(markdown: string): Array<{ cell: string; status: string }> {
  return markdown
    .split('\n')
    .filter((line) => line.startsWith('| ') && !line.includes('---') && !line.includes('Cell'))
    .map((line) => {
      const parts = line.split('|').map((part) => part.trim()).filter((part) => part.length > 0);
      return { cell: parts[0] ?? '', status: parts[1] ?? '' };
    });
}

describe('phase 570 trust pages', () => {
  it('claims only the six existing CI jobs', () => {
    const claimed = rows(text('docs/compatibility.md')).filter((row) => row.status === 'ci');
    expect(claimed.map((row) => row.cell)).toEqual([
      'ubuntu-24.04 / node 22',
      'ubuntu-24.04 / node 24',
      'macos-latest / node 22',
      'macos-latest / node 24',
      'windows-latest / node 22',
      'windows-latest / node 24',
    ]);
    const open = rows(text('docs/compatibility.md')).filter((row) => row.cell === 'bun' || row.cell === 'pnpm' || row.cell === 'yarn' || row.cell === 'npm' || row.cell === 'Express' || row.cell === 'Fastify' || row.cell === 'Nest' || row.cell === 'Next');
    expect(open.every((row) => row.status === 'not claimed')).toBe(true);
    expect(text('.github/workflows/ci.yml')).toContain('node: [22, 24]');
  });

  it('does not put a finding count on the npm audit page', () => {
    const page = text('docs/vs-npm-audit.md');
    expect(page).toContain('reachability');
    expect(page).not.toMatch(/\b\d+\s+findings?\b/i);
  });

  it('keeps the stranger template out of workflows and publishes no quote', () => {
    const page = text('templates/stranger-check.md');
    expect(page).toContain('npx fullshield@<version> --version');
    expect(page).toContain('not a GitHub workflow');
    expect(page).not.toMatch(/"[^"]{8,}"\s+—/);
    expect(() => text('.github/workflows/stranger-check.yml')).toThrow();
  });
});
