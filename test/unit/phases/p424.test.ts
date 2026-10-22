import { createHash } from 'node:crypto';

import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, GITIGNORE_LINE, initGitignore, recordApply, rollback, type JournalEntry } from '../../../src/phases/p424.js';

afterEach(() => {
  delete process.env[FLAG];
});

function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

describe('phase 424 fix rollback journal', () => {
  it('records nothing and leaves the file alone when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(recordApply('before', 'after', 'fix-1')).toEqual({ text: 'after', journal: [] });
    const entry: JournalEntry = {
      id: 'fix-1',
      forward: 'after',
      reverse: 'before',
      hashBefore: sha256('before'),
      hashAfter: sha256('after'),
      restore: 'before',
    };
    expect(rollback(entry, 'after')).toEqual({ text: 'after', refused: false });
  });

  it('journals a scrubbed restore and rolls back the applied text', () => {
    process.env[FLAG] = '1';
    const before = 'key AKIA123 AKIAIOSFODNN7EXAMPLE';
    const after = 'safe';
    const recorded = recordApply(before, after, 'fix-1');
    expect(recorded.text).toBe(after);
    expect(recorded.journal).toHaveLength(1);
    const entry = recorded.journal[0];
    expect(entry?.reverse).toBe('key AKIA123 AKIA****');
    expect(entry?.restore).toBe('key AKIA123 AKIA****');
    expect(entry?.hashBefore).toBe(sha256(before));
    expect(entry?.hashAfter).toBe(sha256(after));
    expect(JSON.stringify(recorded.journal)).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(entry).toBeDefined();
    if (entry === undefined) {
      throw new Error('missing journal entry');
    }
    expect(rollback(entry, after)).toEqual({ text: entry.restore, refused: false });
    expect(initGitignore()).toBe(`${GITIGNORE_LINE}\n`);
  });

  it('refuses rollback when the current text is not the applied hash', () => {
    process.env[FLAG] = '1';
    const recorded = recordApply('before', 'after', 'fix-2');
    const entry = recorded.journal[0];
    expect(entry).toBeDefined();
    if (entry === undefined) {
      throw new Error('missing journal entry');
    }
    expect(rollback(entry, 'after\n')).toEqual({ text: 'after\n', refused: true });
  });
});
