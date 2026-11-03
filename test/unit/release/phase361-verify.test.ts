import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = process.cwd();

function text(name: string): string {
  return readFileSync(join(root, '.github', 'workflows', name), 'utf8');
}

describe('3.6.1 verify matrix', () => {
  it('keeps six verify jobs on a pull request and on main', () => {
    const ci = text('ci.yml');
    const job = ci.slice(ci.indexOf('  verify:'), ci.indexOf('  verify-next:'));
    expect(job).toContain("github.event_name == 'pull_request'");
    expect(job).toContain("github.ref == 'refs/heads/main'");
    expect(job).toContain('os: [ubuntu-24.04, macos-latest, windows-latest]');
    expect(job).toContain('node: [22, 24]');
    expect(job).toContain('npm run verify');
    expect(existsSync(join(root, '.github', 'workflows', 'verify-schedule.yml'))).toBe(false);
  });

  it('does not run npm run verify on a tag', () => {
    const publish = text('publish.yml');
    expect(publish).not.toContain('npm run verify');
    expect(publish).toContain('node scripts/semver-check.mjs');
    expect(publish).toContain('node scripts/pack-budget.mjs');
    expect(publish).toContain('npm run build');
    expect(publish).toContain('node scripts/npm-stage-publish.mjs');
    expect(publish).toContain('node scripts/provenance-gate.mjs');
  });
});
