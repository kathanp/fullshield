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

  it('follows env names and stops on a binding cycle', () => {
    process.env[FLAG] = '1';
    const bindings = [
      { name: 'token', from: 'env' as const, envName: 'API_TOKEN' },
      { name: 'secret', from: 'env' as const, envName: 'SECRET' },
      { name: 'session', from: 'env' as const, envName: 'SESSION_SECRET' },
      { name: 'tok', from: 'env' as const, envName: 'TOKEN' },
      { name: 'custom', from: 'env' as const, envName: 'MY_SECRET' },
      { name: 'plain', from: 'env' as const, envName: 'PORT' },
      { name: 'blank', from: 'env' as const },
      { name: 'loose', from: 'literal' as const },
      { name: 'a', from: 'binding' as const, binding: 'b' },
      { name: 'b', from: 'binding' as const, binding: 'a' },
      { name: 'dangling', from: 'binding' as const },
    ];
    const sinks = ['response', 'bundle', 'error', 'child', 'log'] as const;
    const program = {
      bindings,
      sinks: [
        ...sinks.map((kind, index) => ({ kind, arg: 'token', file: 'a.js', line: index + 1 })),
        { kind: 'log' as const, arg: 'custom', file: 'a.js', line: 8 },
        { kind: 'log' as const, arg: 'plain', file: 'a.js', line: 9 },
        { kind: 'log' as const, arg: 'blank', file: 'a.js', line: 10 },
        { kind: 'log' as const, arg: 'loose', file: 'a.js', line: 11 },
        { kind: 'log' as const, arg: 'a', file: 'a.js', line: 12 },
        { kind: 'log' as const, arg: 'missing', file: 'a.js', line: 13 },
        { kind: 'log' as const, arg: 'dangling', file: 'a.js', line: 14 },
      ],
    };
    const findings = secretFlow(program, formats, { envNames: ['MY_SECRET'] });
    expect(findings.map((finding) => finding.witness)).toEqual([
      'env-name response',
      'env-name client-bundle',
      'env-name error',
      'env-name child-process',
      'env-name log',
      'env-name log',
    ]);
    const chain = Array.from({ length: 34 }, (_, index) => ({
      name: `n${String(index)}`,
      from: 'binding' as const,
      binding: `n${String(index + 1)}`,
    }));
    chain.push({ name: 'n34', from: 'literal', binding: undefined, literal: TOKEN } as unknown as typeof chain[number]);
    expect(secretFlow({
      bindings: chain,
      sinks: [{ kind: 'log', arg: 'n0', file: 'a.js', line: 1 }],
    }, formats)).toEqual([]);
  });
});
