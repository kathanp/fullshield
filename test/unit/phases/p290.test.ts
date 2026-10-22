import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { analyzeEnvSources, enabled, FLAG, scanTreeForEnv } from '../../../src/phases/p290.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');

describe('phase 290 environment sources', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeEnvSources("exec('deploy ' + process.env.BRANCH);").findings).toEqual([]);
  });

  it('reports env flowing to a command and ignores SQL', () => {
    process.env[FLAG] = '1';
    const cmd = analyzeEnvSources("exec('deploy ' + process.env.BRANCH);");
    expect(cmd.findings[0]).toMatchObject({ origin: 'environment', severity: 'info', sinkClass: 'cmdi' });
    expect(cmd.findings[0]?.severity).not.toBe('high');
    const raised = analyzeEnvSources("exec('deploy ' + process.env.BRANCH);", { trustEnvironment: false });
    expect(raised.findings[0]?.severity).toBe('medium');
    expect(analyzeEnvSources("db.query('select ' + process.env.TABLE);").findings).toEqual([]);
  });

  it('stays quiet on clean-app', () => {
    process.env[FLAG] = '1';
    expect(scanTreeForEnv(join(root, 'test/fixtures/clean-app'))).toEqual([]);
  });
});
