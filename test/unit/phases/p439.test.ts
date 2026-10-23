import { afterEach, describe, expect, it } from 'vitest';

import { assertTemplatePolicy, CI_TEMPLATES, enabled, FLAG, templatesForInit } from '../../../src/phases/p439.js';

afterEach(() => {
  delete process.env[FLAG];
});

const passing = 'npx fullshield scan --fail-on high --sarif fullshield.sarif\nimage: node:20@sha256:abc\n';

describe('phase 439 CI templates', () => {
  it('copies no templates when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(templatesForInit()).toEqual({});
  });

  it('ships scan templates that fail on high and store SARIF', () => {
    process.env[FLAG] = '1';
    const copied = templatesForInit();
    expect(Object.keys(copied)).toEqual([
      'templates/Jenkinsfile',
      'templates/circleci.yml',
      'templates/azure-pipelines.yml',
      'templates/bitbucket-pipelines.yml',
    ]);
    for (const text of Object.values(copied)) {
      expect(assertTemplatePolicy(text)).toEqual([]);
      expect(text).not.toContain('createComment');
    }
    expect(copied).toEqual({ ...CI_TEMPLATES });
    expect(assertTemplatePolicy(passing)).toEqual([]);
  });

  it('rejects a missing gate, a comment API, an unpinned image, and a secret', () => {
    process.env[FLAG] = '1';
    expect(assertTemplatePolicy('echo hi')).toEqual(['missing --fail-on high', 'missing artifact path']);
    expect(assertTemplatePolicy(`${passing}createComment()`)).toContain('comment API');
    expect(assertTemplatePolicy(passing.replace('@sha256:abc', ''))).toContain('unpinned image');
    expect(assertTemplatePolicy(`${passing}AKIAIOSFODNN7EXAMPLE`)).toContain('secret-shaped token');
  });
});
