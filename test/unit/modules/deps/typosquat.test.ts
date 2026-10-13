import { describe, expect, it } from 'vitest';

import { findTyposquats } from '../../../../src/modules/deps/typosquat.js';

describe('findTyposquats', () => {
  it('flags a name at Levenshtein distance 1 from a popular package', () => {
    const hits = findTyposquats([{ name: 'expresss', version: '0.0.1', path: 'node_modules/expresss' }]);
    expect(hits).toEqual([
      expect.objectContaining({ name: 'expresss', lookalike: 'express', distance: 1 }),
    ]);
  });

  it('does not flag an exact popular-package name', () => {
    expect(
      findTyposquats([{ name: 'express', version: '4.18.2', path: 'node_modules/express' }]),
    ).toEqual([]);
  });

  it('does not flag names farther than distance 1', () => {
    expect(
      findTyposquats([{ name: 'not-a-real-pkg-zzzz', version: '1.0.0', path: 'node_modules/x' }]),
    ).toEqual([]);
  });
});
