import { describe, expect, it } from 'vitest';

import { deserFinding, deserRuntime, enabled, FLAG } from '../../../src/runtime/exp/p388.js';

describe('phase 388 deserialization', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(deserFinding({ sink: 'node-serialize', origin: 'request' })).toBeNull();
  });

  it('reports node-serialize of a request and emits a runtime event', () => {
    process.env[FLAG] = '1';
    expect(deserFinding({ sink: 'node-serialize', origin: 'request' })?.ruleId).toBe('SAST-EVAL-001');
    expect(deserRuntime({ sink: 'node-serialize', origin: 'request' }, false)).toEqual({ event: true, blocked: false });
  });

  it('ignores a safe yaml schema and a constant document', () => {
    process.env[FLAG] = '1';
    expect(deserFinding({ sink: 'js-yaml', origin: 'request', schema: 'safe' })).toBeNull();
    expect(deserFinding({ sink: 'js-yaml', origin: 'constant', schema: 'default' })).toBeNull();
  });

  it('reports eval of JSON.parse of a request body', () => {
    process.env[FLAG] = '1';
    expect(deserFinding({ sink: 'eval', origin: 'json-parse-request' })).not.toBeNull();
  });
});
