import { describe, expect, it } from 'vitest';

import { exactPinsFromManifest, isExactNpmVersion } from '../../../../src/modules/deps/pins.js';

describe('isExactNpmVersion', () => {
  it('accepts concrete semver and rejects ranges / tags', () => {
    expect(isExactNpmVersion('4.17.11')).toBe(true);
    expect(isExactNpmVersion('=0.0.4')).toBe(true);
    expect(isExactNpmVersion('1.2.3-beta.1')).toBe(true);
    expect(isExactNpmVersion('^4.18.2')).toBe(false);
    expect(isExactNpmVersion('~1.0.0')).toBe(false);
    expect(isExactNpmVersion('>=1.0.0')).toBe(false);
    expect(isExactNpmVersion('latest')).toBe(false);
    expect(isExactNpmVersion('*')).toBe(false);
    expect(isExactNpmVersion('file:../lib')).toBe(false);
  });
});

describe('exactPinsFromManifest', () => {
  it('returns only exact versions from dependency blocks', () => {
    expect(
      exactPinsFromManifest({
        dependencies: { lodash: '4.17.11', express: '^4.18.2' },
        devDependencies: { mocha: '=10.0.0' },
      }),
    ).toEqual([
      { name: 'lodash', version: '4.17.11', path: 'package.json:dependencies' },
      { name: 'mocha', version: '10.0.0', path: 'package.json:devDependencies' },
    ]);
  });
});
