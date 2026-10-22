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
});
