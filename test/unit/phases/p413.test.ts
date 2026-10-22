import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, nosqlGuard } from '../../../src/phases/p413.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 413', () => {
  it('does nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(nosqlGuard({ schema: 'closed', strip: false, constant: false }).edit).toBeNull();
  });

  it('picks a closed schema and refuses a missing key list', () => {
    process.env[FLAG] = '1';
    expect(nosqlGuard({ schema: 'closed', strip: false, constant: false })).toEqual({
      edit: 'pick(filter, ["id"])',
      disposition: 'safe',
    });
    expect(nosqlGuard({ schema: 'none', strip: false, constant: false }).edit).toBeNull();
    expect(nosqlGuard({ schema: 'none', strip: true, constant: false }).disposition).toBe('review');
    expect(nosqlGuard({ schema: 'closed', strip: false, constant: true }).edit).toBeNull();
    expect(nosqlGuard({ schema: 'partial', strip: false, constant: false }).disposition).toBe('review');
  });
});
