import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p350.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 350', () => {
  it('returns undefined when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.bumpCompatibility({ current: '1.0.0', proposed: '2.0.0', imports: [] })).toBeUndefined();
  });

  it('marks a major bump review and a same-major bump mechanical', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.bumpCompatibility({ current: '1.2.0', proposed: '2.0.0', imports: [] })).toBe('review');
    expect(phase.bumpCompatibility({ current: '1.2.0', proposed: '1.3.0', imports: [{ specifier: './ok', dynamic: false }], metadata: { exports: ['./ok'], declarations: [] } })).toBe('mechanical');
  });
});
