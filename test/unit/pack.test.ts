import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = process.cwd();

describe('npm pack contents', () => {
  it('ships dist, README, LICENSE, templates, and rules — not tests or fixtures', () => {
    const result = spawnSync('npm', ['pack', '--dry-run', '--json'], {
      cwd: root,
      encoding: 'utf8',
      shell: process.platform === 'win32',
    });
    expect(result.status).toBe(0);
    const files = JSON.parse(result.stdout) as Array<{ filename: string; files: Array<{ path: string }> }>;
    const paths = (files[0]?.files ?? []).map((f) => f.path);
    expect(paths.some((p) => p === 'README.md' || p.endsWith('/README.md'))).toBe(true);
    expect(paths.some((p) => p.includes('LICENSE'))).toBe(true);
    expect(paths.some((p) => p.startsWith('dist/'))).toBe(true);
    expect(paths.some((p) => p.startsWith('templates/'))).toBe(true);
    expect(paths.some((p) => p.startsWith('rules/'))).toBe(true);
    expect(paths.some((p) => p.startsWith('test/') || p.includes('fixtures/'))).toBe(false);
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    expect(readme).toMatch(/Non-goals/i);
    expect(readme).toMatch(/does \*\*not\*\*|Does \*\*not\*\*/);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
      publishConfig?: { provenance?: boolean };
    };
    expect(pkg.publishConfig?.provenance).toBeUndefined();
  });
});

