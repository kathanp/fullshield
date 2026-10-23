import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, rewriteExec } from '../../../src/phases/p408.js';

const git = "exec('git show ' + rev)";

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 408', () => {
  it('does nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(rewriteExec(git, 'safe-git').source).toBe(git);
  });

  it('rewrites git with end-of-options and refuses the other shapes', () => {
    process.env[FLAG] = '1';
    const rewritten = rewriteExec(git, 'safe-git');
    expect(rewritten.source).toBe("execFile('git', ['show', '--', rev])");
    expect(rewriteExec("exec('ls ' + name)", 'bare').refused).toBe(true);
    expect(rewriteExec("exec('cat a | wc')", 'pipe').source).toBe("exec('cat a | wc')");
    expect(rewriteExec("execFile('git', ['status'])", 'already-execFile').source).toBe("execFile('git', ['status'])");
    expect(rewriteExec('exec(cmd)', 'unknown-program').refused).toBe(true);
  });
});
