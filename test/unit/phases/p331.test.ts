import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, secretFlow, type FlowProgram } from '../../../src/phases/p331.js';
import { FLAG as FORMAT_FLAG, type SecretFormat } from '../../../src/phases/p332.js';

const TOKEN = 'fsyn_ABCDEFGHIJKLMNOP';
const formats: SecretFormat[] = [{
  id: 'synth',
  source: 'https://example.invalid/grammar',
  prefix: 'fsyn_',
  alphabet: 'A-Za-z0-9',
  length: 16,
  notBeforeLength: 21,
  synthetic: [{ value: TOKEN, synthetic: true }],
}];

function program(sink: FlowProgram['sinks'][number]['kind'], arg = 'token'): FlowProgram {
  return {
    bindings: [{ name: 'token', from: 'literal', literal: TOKEN }],
    sinks: [{ kind: sink, arg, file: 'a.js', line: 3 }],
  };
}

afterEach(() => {
  delete process.env[FLAG];
  delete process.env[FORMAT_FLAG];
});

describe('phase 331 secret flow', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(secretFlow(program('log'), formats)).toEqual([]);
  });

  it('reports a logger sink and a helper copy, and ignores hmac', () => {
    process.env[FLAG] = '1';
    const logged = secretFlow(program('log'), formats);
    expect(logged[0]?.witness).toContain('log');
    expect(JSON.stringify(logged)).not.toContain(TOKEN);
    const copied = secretFlow({
      bindings: [
        { name: 'token', from: 'literal', literal: TOKEN },
        { name: 'copy', from: 'binding', binding: 'token' },
      ],
      sinks: [{ kind: 'log', arg: 'copy', file: 'a.js', line: 4 }],
    }, formats);
    expect(copied).toHaveLength(1);
    expect(secretFlow(program('hmac'), formats)).toEqual([]);
  });

  it('does not treat NODE_ENV or a prefix plus example as a secret', () => {
    process.env[FLAG] = '1';
    const env = secretFlow({
      bindings: [{ name: 'mode', from: 'env', envName: 'NODE_ENV' }],
      sinks: [{ kind: 'log', arg: 'mode', file: 'a.js', line: 1 }],
    }, formats);
    expect(env).toEqual([]);
    const prefix = secretFlow({
      bindings: [{ name: 'token', from: 'literal', literal: 'fsyn_example' }],
      sinks: [{ kind: 'log', arg: 'token', file: 'a.js', line: 1 }],
    }, formats);
    expect(prefix).toEqual([]);
  });
});
