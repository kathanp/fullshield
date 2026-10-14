import { describe, expect, it } from 'vitest';

import { applyReplacement, unifiedDiff } from '../../../src/fixer/diff.js';

describe('unifiedDiff / applyReplacement', () => {
  it('returns an empty string when before and after are identical', () => {
    expect(unifiedDiff('a.js', 'same\n', 'same\n')).toBe('');
  });

  it('emits a single-file unified diff and applyReplacement returns the after text', () => {
    const diff = unifiedDiff('a.js', 'old\n', 'new\n');
    expect(diff).toContain('--- a/a.js');
    expect(diff).toContain('+++ b/a.js');
    expect(diff).toContain('-old');
    expect(diff).toContain('+new');
    expect(applyReplacement('old\n', 'new\n')).toBe('new\n');
  });
});
