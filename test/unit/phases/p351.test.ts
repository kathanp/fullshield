import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p351.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 351', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.reproFindings([{ name: 'left', range: '^1.0.0', locked: '1.0.0', versions: ['1.2.0'], direct: true }]).findings).toEqual([]);
  });

  it('reports a lock that is not the highest match and skips an indirect dep', () => {
    process.env[phase.FLAG] = '1';
    const hit = phase.reproFindings([{ name: 'left', range: '^1.0.0', locked: '1.0.0', versions: ['1.0.0', '1.2.0'], direct: true }]);
    expect(hit.findings[0]?.ruleId).toBe(phase.RULE);
    expect(phase.reproFindings([{ name: 'left', range: '^1.0.0', locked: '1.0.0', versions: ['1.2.0'], direct: false }]).findings).toEqual([]);
  });

  it('skips a dist-tag and records a missing packument', () => {
    process.env[phase.FLAG] = '1';
    const tag = phase.reproFindings([{ name: 'left', range: 'latest', locked: '1.0.0', versions: ['1.0.0'], direct: true }]);
    expect(tag.events).toEqual([{ code: 271, file: 'left', detail: 'dist-tag is not a version' }]);
    expect(tag.findings).toEqual([]);
    const caret = phase.reproFindings([{ name: 'left', range: '^nope', locked: '1.0.0', versions: ['1.0.0'], direct: true }]);
    expect(caret.events[0]?.detail).toBe('missing packument');
    const tilde = phase.reproFindings([{ name: 'left', range: '~nope', direct: true, versions: ['1.0.0'] }]);
    expect(tilde.events[0]?.detail).toBe('missing packument');
    const digit = phase.reproFindings([{ name: 'left', range: '1', locked: '1.0.0', versions: ['1.0.0'], direct: true }]);
    expect(digit.events[0]?.detail).toBe('missing packument');
  });

  it('records a missing packument when versions or the lock are absent and accepts an exact match', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.reproFindings([{ name: 'left', range: '^1.0.0', locked: '1.0.0', direct: true }]).events[0]?.detail).toBe('missing packument');
    expect(phase.reproFindings([{ name: 'left', range: '^1.0.0', versions: ['1.0.0', '1.2.0'], direct: true }]).events[0]?.detail).toBe('missing packument');
    expect(phase.reproFindings([{ name: 'left', range: '^9.0.0', locked: '1.0.0', versions: ['1.0.0'], direct: true }]).events[0]?.detail).toBe('missing packument');
    const match = phase.reproFindings([{ name: 'left', range: '^1.0.0', locked: '1.2.0', versions: ['1.0.0', '1.2.0', '1.1.0'], direct: true }]);
    expect(match).toEqual({ findings: [], events: [] });
  });
});
