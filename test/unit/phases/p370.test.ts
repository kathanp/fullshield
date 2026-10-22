import { describe, expect, it } from 'vitest';

import { enabled, FLAG, orderFixes, type FixProposal } from '../../../src/phases/p370.js';

const proposals: FixProposal[] = [
  { packageName: 'm', reachability: 'not-imported', severity: 'critical' },
  { packageName: 'a', reachability: 'reachable', severity: 'low' },
  { packageName: 'z', reachability: 'function-reachable-via-dependency', severity: 'high' },
  { packageName: 'b', reachability: 'reachability-unknown', severity: 'medium' },
  { packageName: 'c', reachability: 'reachable', severity: 'info', runtimeObserved: true },
];

describe('phase 370 fix order', () => {
  it('keeps the previous order when the flag is off', () => {
    expect(enabled()).toBe(false);
    const ordered = orderFixes(proposals);
    expect(ordered.header).toBe('');
    expect(ordered.proposals.map((row) => row.packageName)).toEqual(['m', 'a', 'z', 'b', 'c']);
  });

  it('sorts by the reachability key and prints that key', () => {
    process.env[FLAG] = '1';
    const ordered = orderFixes(proposals);
    expect(ordered.header).toBe('order: reachability');
    expect(ordered.proposals.map((row) => row.packageName)).toEqual(['c', 'z', 'a', 'b', 'm']);
  });

  it('sorts by severity then name', () => {
    process.env[FLAG] = '1';
    const ordered = orderFixes(proposals, 'severity');
    expect(ordered.header).toBe('order: severity');
    expect(ordered.proposals.map((row) => row.packageName)).toEqual(['m', 'z', 'b', 'a', 'c']);
  });
});
