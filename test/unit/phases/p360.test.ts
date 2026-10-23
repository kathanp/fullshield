import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p360.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 360', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.repoMismatch({ packageName: 'left', packument: 'https://github.com/a/b', tarball: 'https://gitlab.com/a/b' }).findings).toEqual([]);
  });

  it('reports a host mismatch and treats a git suffix as the same url', () => {
    process.env[phase.FLAG] = '1';
    const hit = phase.repoMismatch({ packageName: 'left', packument: 'https://github.com/a/b', tarball: 'https://gitlab.com/a/b' });
    expect(hit.findings[0]?.ruleId).toBe(phase.RULE);
    expect(hit.findings[0]?.message).not.toContain('star');
    expect(phase.repoMismatch({ packageName: 'left', packument: 'git+https://github.com/a/b.git', tarball: 'https://github.com/a/b' }).findings).toEqual([]);
    expect(phase.repoMismatch({ packageName: 'left', packument: 'https://github.com/a/b', tarball: null }).events[0]?.code).toBe(271);
  });

  it('normalizes scp and ssh urls and compares a third git url', () => {
    process.env[phase.FLAG] = '1';
    const scp = phase.repoMismatch({
      packageName: 'left',
      packument: 'git@github.com:a/b.git',
      tarball: 'https://github.com/a/b/',
    });
    expect(scp.findings).toEqual([]);
    const ssh = phase.repoMismatch({
      packageName: 'left',
      packument: 'ssh://git@github.com/a/b#readme',
      tarball: 'http://GitHub.com/a/b',
    });
    expect(ssh.findings).toEqual([]);
    const plainSsh = phase.repoMismatch({
      packageName: 'left',
      packument: 'ssh://github.com/a/b',
      tarball: 'https://github.com/a/b',
    });
    expect(plainSsh.findings).toEqual([]);
    const git = phase.repoMismatch({
      packageName: 'left',
      packument: 'https://github.com/a/b',
      tarball: 'https://github.com/a/b',
      git: 'https://gitlab.com/a/b',
    });
    expect(git.findings[0]?.urls).toEqual(['https://github.com/a/b', 'https://gitlab.com/a/b']);
    expect(phase.repoMismatch({
      packageName: 'left',
      packument: 'https://github.com/a/b',
      tarball: 'https://github.com/a/b',
      git: null,
    }).findings).toEqual([]);
  });
});
