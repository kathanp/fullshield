import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = process.cwd();

/** npm 11: `[{ files }]`. npm 12+: `{ "<name>": { files } }`. */
function packedPaths(stdout: string): string[] {
  const listing = JSON.parse(stdout) as unknown;
  const entry = Array.isArray(listing)
    ? (listing[0] as { files?: Array<{ path: string }> } | undefined)
    : listing && typeof listing === 'object'
      ? (Object.values(listing as Record<string, { files?: Array<{ path: string }> }>)[0] ?? undefined)
      : undefined;
  return (entry?.files ?? []).map((f) => f.path);
}

describe('npm pack contents', () => {
  it('ships dist, README, LICENSE, templates, and rules — not tests or fixtures', () => {
    const result = spawnSync('npm', ['pack', '--dry-run', '--json'], {
      cwd: root,
      encoding: 'utf8',
      shell: process.platform === 'win32',
    });
    expect(result.status).toBe(0);
    const paths = packedPaths(result.stdout);
    // Packument `readme` is extracted from a root README.md. Nested or missing
    // files leave npm's packument as `"readme": ""`.
    expect(paths).toContain('README.md');
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
      bin?: { fullshield?: string };
      readme?: string;
      publishConfig?: { provenance?: boolean };
    };
    expect(pkg.readme === undefined || pkg.readme === 'README.md').toBe(true);
    expect(pkg.readme).not.toBe('');
    expect(pkg.publishConfig?.provenance).toBeUndefined();
    // npm 11+ drops `./` bin paths ("script name … was invalid and removed") so npx would have no command.
    expect(pkg.bin?.fullshield).toBe('dist/cli/index.js');
  });

  it('does not ship source maps', () => {
    const result = spawnSync('npm', ['pack', '--dry-run', '--json'], {
      cwd: root,
      encoding: 'utf8',
      shell: process.platform === 'win32',
    });
    expect(result.status).toBe(0);
    const paths = packedPaths(result.stdout);
    expect(paths.some((p) => p.endsWith('.map'))).toBe(false);
  });
});

