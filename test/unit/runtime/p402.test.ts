import { describe, expect, it } from 'vitest';

import { BUILD_HASH, checkIntegrity, enabled, FLAG, hashSource, INSTALLER_SOURCE } from '../../../src/runtime/exp/p402.js';

describe('phase 402 hook integrity', () => {
  it('does not check when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(checkIntegrity('mutated', { refuseOnMismatch: true }).listen).toBe(true);
  });

  it('matches a fresh hash of the shipped source', () => {
    process.env[FLAG] = '1';
    expect(hashSource(INSTALLER_SOURCE)).toBe(BUILD_HASH);
    expect(checkIntegrity(INSTALLER_SOURCE).listen).toBe(true);
    expect(checkIntegrity(INSTALLER_SOURCE).critical).toBe(false);
  });

  it('logs critical on a mutated file and still listens unless configured', () => {
    process.env[FLAG] = '1';
    const mutated = checkIntegrity(`${INSTALLER_SOURCE}\n`);
    expect(mutated.critical).toBe(true);
    expect(mutated.listen).toBe(true);
    expect(checkIntegrity(`${INSTALLER_SOURCE}\n`, { refuseOnMismatch: true }).listen).toBe(false);
  });
});
