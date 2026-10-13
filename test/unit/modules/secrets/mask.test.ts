import { describe, expect, it } from 'vitest';

import { foldStringConcat, maskSecret, shannonEntropy } from '../../../../src/modules/secrets/mask.js';

describe('maskSecret', () => {
  it('keeps the first 4 chars and masks the rest', () => {
    expect(maskSecret('AKIA' + 'IOSFODNN7EXAMPLE')).toBe('AKIA****');
    expect(maskSecret('sk_test_abcdefgh')).toBe('sk_t****');
  });

  it('never reveals anything beyond 4 chars', () => {
    const secret = 'supersecretvalue1234';
    const masked = maskSecret(secret);
    expect(masked).toBe('supe****');
    expect(masked).not.toContain(secret.slice(4));
  });

  it('masks very short values entirely past their first chars', () => {
    expect(maskSecret('abc')).toBe('abc****');
  });
});

describe('foldStringConcat', () => {
  it('folds adjacent string-literal concatenation', () => {
    expect(foldStringConcat("const k = 'AKIA' + 'IOSFODNN7EXAMPLE';")).toContain(
      'AKIA' + 'IOSFODNN7EXAMPLE',
    );
    expect(foldStringConcat('const k = "sk_test_" + "FAKEfake";')).toContain('sk_test_FAKEfake');
  });

  it('leaves non-literal concatenation alone', () => {
    const line = "const k = prefix + 'suffix';";
    expect(foldStringConcat(line)).toBe(line);
  });
});

describe('shannonEntropy', () => {
  it('is low for repetitive strings', () => {
    expect(shannonEntropy('aaaaaaaaaaaaaaaaaaaaaaaa')).toBeLessThan(1);
  });

  it('is high for random-looking strings', () => {
    expect(shannonEntropy('aB3dE5gH7jK9mN1pQ4sU6wX8')).toBeGreaterThan(4.5);
  });

  it('is 0 for the empty string', () => {
    expect(shannonEntropy('')).toBe(0);
  });
});
