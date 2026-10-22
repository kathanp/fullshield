import { afterEach, describe, expect, it } from 'vitest';

import { enabled, explainWitness, FLAG, STEP_CAP, type ExplainWitness } from '../../../src/phases/p443.js';

afterEach(() => {
  delete process.env[FLAG];
});

function witness(over: Partial<ExplainWitness> = {}): ExplainWitness {
  return {
    fingerprint: 'fp-1',
    sourceFile: 'src/req.js',
    sinkFile: 'src/db.js',
    steps: ['read req.query', 'reach db.query'],
    sanitizers: ['bind'],
    sink: 'db.query',
    ...over,
  };
}

describe('phase 443 witness diagrams', () => {
  it('errors with FS-E when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(explainWitness('fp-1', [witness()])).toEqual({
      exitCode: 1,
      code: 'FS-E',
      text: 'FS-E explain is experimental',
    });
  });

  it('prints the source, steps, sanitizers, and sink', () => {
    process.env[FLAG] = '1';
    const result = explainWitness('fp-1', [witness()]);
    expect(result.exitCode).toBe(0);
    expect(result.text).toBe(
      ['source: src/req.js', 'steps:', '- read req.query', '- reach db.query', 'sanitizers:', '- bind', 'sink: src/db.js', 'db.query'].join('\n'),
    );
  });

  it('rejects an unknown fingerprint and caps a long witness', () => {
    process.env[FLAG] = '1';
    const missing = explainWitness('missing', [witness()]);
    expect(missing.exitCode).toBe(1);
    expect(missing.code).toBe('FS-E');
    expect(missing.text).toBe('FS-E unknown fingerprint missing');
    const steps = Array.from({ length: STEP_CAP + 1 }, (_unused, index) => (index === 0 ? 'carry AKIAIOSFODNN7EXAMPLE' : `step ${index}`));
    const long = explainWitness('fp-long', [witness({ fingerprint: 'fp-long', steps, secretToken: 'AKIAIOSFODNN7EXAMPLE' })]);
    expect(long.exitCode).toBe(0);
    expect(long.text).toContain('witness was truncated');
    expect(long.text).toContain(`- step ${STEP_CAP - 1}`);
    expect(long.text).not.toContain(`- step ${STEP_CAP}`);
    expect(long.text).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(long.text).toContain('fingerprint: fp-long');
  });
});
