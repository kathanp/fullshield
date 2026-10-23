import { describe, expect, it } from 'vitest';

import { enabled, FLAG, mongoOperatorEvent } from '../../../src/runtime/exp/p384.js';

describe('phase 384 mongo operators', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(mongoOperatorEvent({ $where: '1' }, 'request')).toBe(false);
  });

  it('reports a request filter that contains $where', () => {
    process.env[FLAG] = '1';
    expect(mongoOperatorEvent({ $where: 'this.a == 1' }, 'request')).toBe(true);
  });

  it('ignores a constant filter and a value that merely contains $where', () => {
    process.env[FLAG] = '1';
    expect(mongoOperatorEvent({ status: 'open' }, 'constant')).toBe(false);
    expect(mongoOperatorEvent({ title: '$where' }, 'request')).toBe(false);
  });
});
