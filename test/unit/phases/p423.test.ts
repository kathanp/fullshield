import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, reviewFixes, type FixBatch, type ReviewRequest } from '../../../src/phases/p423.js';

afterEach(() => {
  delete process.env[FLAG];
});

function batch(id: string, disposition: 'safe' | 'review'): FixBatch {
  return { id, disposition, diff: `diff ${id}`, path: `${id}.js`, nextText: `next ${id}` };
}

function request(over: Partial<ReviewRequest> = {}): ReviewRequest {
  return {
    batches: [batch('safe-one', 'safe'), batch('review-one', 'review')],
    stdin: '',
    apply: false,
    applyReview: false,
    interactive: false,
    ...over,
  };
}

describe('phase 423 terminal fix review', () => {
  it('writes the previous safe set when the flag is off', () => {
    expect(enabled()).toBe(false);
    const applied = reviewFixes(request({ apply: true }));
    expect(applied.exitCode).toBe(0);
    expect(applied.writes).toEqual([{ path: 'safe-one.js', text: 'next safe-one' }]);
    expect(applied.listened).toBe(false);
    expect(applied.browser).toBe(false);
    expect(reviewFixes(request()).writes).toEqual([]);
  });

  it('applies a confirmed batch and an explicit review apply', () => {
    process.env[FLAG] = '1';
    const prompted = reviewFixes(request({ interactive: true, stdin: 'y\n\n' }));
    expect(prompted.exitCode).toBe(0);
    expect(prompted.writes).toEqual([{ path: 'safe-one.js', text: 'next safe-one' }]);
    expect(prompted.output).toContain('Apply? [y/N]');
    expect(prompted.output).toContain('diff review-one');
    expect(prompted.listened).toBe(false);
    expect(prompted.browser).toBe(false);
    const reviewed = reviewFixes(request({ apply: true, applyReview: true }));
    expect(reviewed.exitCode).toBe(0);
    expect(reviewed.writes.map((row) => row.path)).toEqual(['safe-one.js', 'review-one.js']);
  });

  it('treats a blank answer as no and refuses a review batch', () => {
    process.env[FLAG] = '1';
    const blank = reviewFixes(request({ interactive: true, stdin: '\nY' }));
    expect(blank.writes).toEqual([]);
    const refused = reviewFixes(request({ apply: true, applyReview: false }));
    expect(refused.exitCode).toBe(1);
    expect(refused.writes).toEqual([]);
    expect(refused.output).toContain('--apply-review');
    expect(refused.browser).toBe(false);
  });
});
