import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { formatCliError } from '../../../../src/cli/errors.js';
import { scan } from '../../../../src/core/engine.js';
import { guardSemgrepCli } from '../../../../src/modules/sast/semgrep/flag.js';
import { loadUserSemgrepRules } from '../../../../src/modules/sast/semgrep/load.js';

const app = join(import.meta.dirname, '../../../fixtures/semgrep-rules-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_SEMGREP_RULES';

const cases: Array<{ id: string; pos: string; neg: string; severity: string }> = [
  { id: 'CUSTOM-js-direct-eval', pos: 'src/eval-hit.js', neg: 'src/eval-miss.js', severity: 'high' },
  { id: 'CUSTOM-ts-danger', pos: 'src/danger-hit.ts', neg: 'src/danger-miss.ts', severity: 'high' },
  { id: 'CUSTOM-either-launch', pos: 'src/either-hit.js', neg: 'src/either-miss.js', severity: 'high' },
  { id: 'CUSTOM-query-not-fixed', pos: 'src/query-hit.js', neg: 'src/query-miss.js', severity: 'high' },
  { id: 'CUSTOM-send-inside-handler', pos: 'src/send-hit.js', neg: 'src/send-miss.js', severity: 'medium' },
  { id: 'CUSTOM-read-with-tail', pos: 'src/read-hit.js', neg: 'src/read-miss.js', severity: 'medium' },
  { id: 'CUSTOM-pair-same', pos: 'src/pair-hit.js', neg: 'src/pair-miss.js', severity: 'high' },
  { id: 'CUSTOM-tainted-eval', pos: 'src/taint-hit.js', neg: 'src/taint-miss.js', severity: 'high' },
  { id: 'CUSTOM-ticket-to-run', pos: 'src/ticket-hit.js', neg: 'src/ticket-miss.js', severity: 'high' },
  { id: 'CUSTOM-run-not-fixed', pos: 'src/run-hit.js', neg: 'src/run-miss.js', severity: 'high' },
];

const rejected: Array<{ config: string; construct: string; ruleId: string }> = [
  { config: 'regex.config.json', construct: 'pattern-regex', ruleId: 'bad-regex' },
  { config: 'meta.config.json', construct: 'metavariable-regex', ruleId: 'bad-meta' },
  { config: 'python.config.json', construct: 'python', ruleId: 'bad-python' },
];

describe('phase 90 user semgrep rules', () => {
  afterEach(() => {
    delete process.env[FLAG];
  });

  it('does not parse the rules file when the flag is off', async () => {
    const missing = join(app, 'no-such-rules.yml');
    await expect(loadUserSemgrepRules(missing, false)).resolves.toEqual([]);
    const result = await scan({
      cwd: app,
      modules: ['sast'],
      configPath: join(app, 'flag-off.config.json'),
    });
    expect(result.findings.some((finding) => finding.source === 'user-rule' || finding.ruleId.startsWith('CUSTOM-'))).toBe(
      false,
    );
  });

  it('matches every hand-written rule on its positive fixture only', async () => {
    process.env[FLAG] = '1';
    const result = await scan({ cwd: app, modules: ['sast'] });
    for (const row of cases) {
      const hits = result.findings.filter((finding) => finding.ruleId === row.id);
      expect(hits.map((finding) => finding.file)).toContain(row.pos);
      expect(hits.map((finding) => finding.file)).not.toContain(row.neg);
      const positive = hits.find((finding) => finding.file === row.pos);
      expect(positive?.severity).toBe(row.severity);
      expect(positive?.source).toBe('user-rule');
    }
    expect(result.findings.some((finding) => finding.ruleId === 'CUSTOM-js-direct-eval' && finding.file === 'src/eval-only.ts')).toBe(
      false,
    );
  });

  it.each(rejected)('rejects $construct in rule $ruleId', async ({ config, construct, ruleId }) => {
    process.env[FLAG] = '1';
    await expect(
      scan({
        cwd: app,
        modules: ['sast'],
        configPath: join(app, 'rejected', config),
      }),
    ).rejects.toThrow(new RegExp(`unsupported construct "${construct}"[\\s\\S]*rule "${ruleId}"`));
  });

  it('rejects the whole rules file when any rule is unsupported', async () => {
    process.env[FLAG] = '1';
    const error = await scan({
      cwd: app,
      modules: ['sast'],
      configPath: join(app, 'rejected', 'mixed.config.json'),
    }).then(
      () => {
        throw new Error('mixed rules file was applied');
      },
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(Error);
    const message = error instanceof Error ? error.message : '';
    expect(message).toMatch(/unsupported construct "pattern-where"/);
    expect(message).toMatch(/rule "bad-where"/);
    expect(formatCliError(error)).toMatch(/FS-E012/);
    expect(() => guardSemgrepCli('rejected/bad-mixed.yml', false)).toThrow(/FULLSHIELD_EXPERIMENTAL_SEMGREP_RULES/);
  });

  it('documents the supported subset and that results may differ from Semgrep', () => {
    const doc = readFileSync(join(import.meta.dirname, '../../../../docs/semgrep-subset.md'), 'utf8');
    for (const phrase of [
      'javascript',
      'typescript',
      'pattern-either',
      'pattern-not',
      'pattern-inside',
      'pattern-sources',
      'pattern-sinks',
      'pattern-sanitizers',
      'mode: taint',
      '$X',
      '...',
      'CUSTOM-',
      'user-rule',
      'may differ from Semgrep',
    ]) {
      expect(doc).toContain(phrase);
    }
  });
});
