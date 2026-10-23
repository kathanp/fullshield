import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, groupFixes, type BatchEdit } from '../../../src/phases/p420.js';

function edit(dir: string, disposition: 'safe' | 'review', lines = 10): BatchEdit {
  return { dir, ruleId: 'SAST-SQLI-001', lines, disposition, path: `${dir}/a.js` };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 420', () => {
  it('does nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(groupFixes([edit('src', 'safe')]).batches).toEqual([]);
  });

  it('splits directories and refuses a path that escapes the batch', () => {
    process.env[FLAG] = '1';
    const edits = [
      ...Array.from({ length: 5 }, () => edit('src', 'safe')),
      ...Array.from({ length: 5 }, () => edit('lib', 'safe')),
    ];
    expect(groupFixes(edits).batches).toHaveLength(2);
    expect(groupFixes([edit('src', 'safe'), edit('src', 'review')]).batches[0]?.disposition).toBe('review');
    expect(groupFixes([{ ...edit('src', 'safe'), path: '../passwd' }]).refused).toBe(true);
    expect(groupFixes([edit('src', 'safe', 300), edit('src', 'safe', 300)], 400).batches).toHaveLength(2);
    const file = readFileSync(new URL('../../../src/phases/p420.ts', import.meta.url), 'utf8');
    expect(file.includes('git push')).toBe(false);
  });
});
