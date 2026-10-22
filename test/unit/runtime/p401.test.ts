import { describe, expect, it } from 'vitest';

import { enabled, FLAG, maskResponse, responseFinding } from '../../../src/runtime/exp/p401.js';

describe('phase 401 response masking', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(responseFinding(['password'], ['password'])).toBeNull();
  });

  it('reports a model password on res.json and ignores a DTO that omitted it', () => {
    process.env[FLAG] = '1';
    expect(responseFinding(['password', 'name'], ['password', 'name'])?.field).toBe('password');
    expect(responseFinding(['password', 'name'], ['name'])).toBeNull();
  });

  it('strips only when asked and does not log the value', () => {
    process.env[FLAG] = '1';
    const secret = 's3cret-value';
    const stripped = maskResponse({ password: secret, name: 'ada' }, { strip: true });
    expect(stripped.body).toEqual({ name: 'ada' });
    expect(stripped.log).not.toContain(secret);
    const kept = maskResponse({ password: secret, name: 'ada' }, { strip: false });
    expect(kept.body.password).toBe(secret);
  });
});
