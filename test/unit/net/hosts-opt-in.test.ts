import { afterEach, describe, expect, it } from 'vitest';

import { isAllowlistedHost } from '../../../src/net/hosts.js';

const FLAGS = ['FULLSHIELD_AI_LIVE', 'FULLSHIELD_EXPERIMENTAL_SECRETS_ADV'] as const;

afterEach(() => {
  for (const flag of FLAGS) delete process.env[flag];
});

describe('opt-in hosts', () => {
  it('rejects AI and secret-verify hosts while their flags are off', () => {
    expect(isAllowlistedHost('api.anthropic.com')).toBe(false);
    expect(isAllowlistedHost('api.openai.com')).toBe(false);
    expect(isAllowlistedHost('sts.amazonaws.com')).toBe(false);
    expect(isAllowlistedHost('api.github.com')).toBe(false);
    expect(isAllowlistedHost('api.stripe.com')).toBe(false);
    expect(isAllowlistedHost('slack.com')).toBe(false);
  });

  it('allowlists an AI host only while FULLSHIELD_AI_LIVE=1', () => {
    process.env.FULLSHIELD_AI_LIVE = '1';
    expect(isAllowlistedHost('api.anthropic.com')).toBe(true);
    expect(isAllowlistedHost('api.openai.com')).toBe(true);
    expect(isAllowlistedHost('sts.amazonaws.com')).toBe(false);
  });

  it('allowlists secret-verify hosts only while FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1', () => {
    process.env.FULLSHIELD_EXPERIMENTAL_SECRETS_ADV = '1';
    expect(isAllowlistedHost('sts.amazonaws.com')).toBe(true);
    expect(isAllowlistedHost('api.github.com')).toBe(true);
    expect(isAllowlistedHost('api.stripe.com')).toBe(true);
    expect(isAllowlistedHost('slack.com')).toBe(true);
    expect(isAllowlistedHost('api.anthropic.com')).toBe(false);
  });
});
