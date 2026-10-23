import { beforeEach, describe, expect, it } from 'vitest';

import { catalogConcat, checkSink, enabled, FLAG, labelSource, resetLabels, throughUncatalogued, unboxCount } from '../../../src/runtime/exp/p382.js';

beforeEach(() => {
  resetLabels();
});

describe('phase 382 runtime labels', () => {
  it('does not wrap when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(typeof labelSource('payload', 'request')).toBe('string');
    expect(checkSink('sql', 'payload', true).blocked).toBe(false);
  });

  it('blocks a payload that passes through one catalog transfer', () => {
    process.env[FLAG] = '1';
    const labeled = labelSource("' OR '1", 'request');
    expect(typeof labeled).toBe('string');
    const transferred = catalogConcat([labeled, 'x']);
    const decision = checkSink('sql', transferred, true);
    expect(decision.blocked).toBe(true);
    expect(decision.event).not.toHaveProperty('body');
    expect(JSON.stringify(decision.event)).not.toContain('OR');
  });

  it('does not block an uncatalogued helper and increments the unbox counter', () => {
    process.env[FLAG] = '1';
    const labeled = labelSource('payload', 'request');
    const leaked = throughUncatalogued(labeled, (value) => value.toUpperCase());
    expect(unboxCount()).toBe(1);
    expect(checkSink('sql', leaked, true).blocked).toBe(false);
  });

  it('lets an unlabeled benign string through', () => {
    process.env[FLAG] = '1';
    expect(checkSink('sql', catalogConcat(['hello']), true).blocked).toBe(false);
  });
});
