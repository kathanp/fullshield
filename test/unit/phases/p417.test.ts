import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, helmetFix } from '../../../src/phases/p417.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 417', () => {
  it('does nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(helmetFix({ express: true, helmet: false, reflect: false, foreignScript: false, apply: false }).dryRun).toBe('');
  });

  it('dry-runs helmet and refuses an invented origin', () => {
    process.env[FLAG] = '1';
    const dry = helmetFix({ express: true, helmet: false, reflect: false, foreignScript: false, apply: false });
    expect(dry.dryRun).toContain('helmet()');
    expect(dry.disposition).toBe('review');
    expect(dry.insertedOriginTrue).toBe(false);
    const reflect = helmetFix({ express: true, helmet: true, reflect: true, foreignScript: false, apply: true });
    expect(reflect.applied).toBe(false);
    expect(reflect.dryRun.includes('example.com')).toBe(false);
    const foreign = helmetFix({ express: true, helmet: true, reflect: false, foreignScript: true, apply: true });
    expect(foreign.dryRun.includes('origin: false')).toBe(false);
  });
});
