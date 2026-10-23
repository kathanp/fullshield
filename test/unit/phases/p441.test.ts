import { afterEach, describe, expect, it } from 'vitest';

import { checkConfig, enabled, FLAG, runtimeSchemaPath, scannerSchemaPath, SCHEMA_PATH, schemaPropertyNames } from '../../../src/phases/p441.js';

afterEach(() => {
  delete process.env[FLAG];
});

const valid = {
  modules: ['sast'],
  failOn: 'high',
  notify: { slackWebhookEnv: 'SLACK_WEBHOOK' },
  deps: { offline: true },
};

describe('phase 441 config schema', () => {
  it('errors with FS-E and does not validate when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(checkConfig({ score: 1 })).toEqual({ ok: false, exitCode: 1, code: 'FS-E', errors: [] });
    expect(scannerSchemaPath()).toBe(runtimeSchemaPath());
    expect(scannerSchemaPath()).toBe(SCHEMA_PATH);
  });

  it('accepts the keys the scanner already reads', () => {
    process.env[FLAG] = '1';
    expect(checkConfig(valid)).toEqual({ ok: true, exitCode: 0, errors: [] });
    expect(schemaPropertyNames()).toEqual([
      'modules',
      'failOn',
      'ignore',
      'defaultExcludes',
      'excludes',
      'baseline',
      'notify',
      'deps',
      'ai',
      'sast',
      'types',
      'semgrepRules',
    ]);
    expect(schemaPropertyNames()).not.toContain('score');
  });

  it('rejects an unknown key', () => {
    process.env[FLAG] = '1';
    expect(checkConfig({ score: 1, notify: { url: 'http://example.invalid' } })).toEqual({
      ok: false,
      exitCode: 1,
      errors: ['config: unknown key "score"', 'config.notify: unknown key "url"'],
    });
  });
});
