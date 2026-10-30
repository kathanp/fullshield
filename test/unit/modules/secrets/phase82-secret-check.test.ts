import { crc32 } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { DEFAULT_CONFIG } from '../../../../src/core/config.js';
import type { ScanResult } from '../../../../src/core/engine.js';
import type { Finding } from '../../../../src/core/finding.js';
import { scanTextForSecrets } from '../../../../src/modules/secrets/index.js';
import { isActionable, renderConsoleReport } from '../../../../src/reporters/console.js';
import { renderJsonReport } from '../../../../src/reporters/json.js';

/**
 * GitHub token checksum from the public format doc (never a live token):
 * https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
 * CRC-32/IEEE of the body excluding the last 6 characters, base62, alphabet 0-9A-Za-z.
 */
const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const FLAG = 'FULLSHIELD_EXPERIMENTAL_SECRET_CHECK';
const AWS_EXAMPLE = 'AKIA' + 'IOSFODNN7EXAMPLE';

function base62Crc(data: string): string {
  let n = crc32(data) >>> 0;
  let out = '';
  for (let i = 0; i < 6; i += 1) {
    out = ALPHABET[n % 62] + out;
    n = Math.floor(n / 62);
  }
  return out;
}

function classicToken(prefix: string, body30: string): string {
  return `${prefix}_${body30}${base62Crc(body30)}`;
}

function fineToken(body76: string): string {
  return `github_pat_${body76}${base62Crc(body76)}`;
}

function oneOff(token: string, index: number): string {
  const chars = token.split('');
  const current = chars[index];
  if (current === undefined) throw new Error('index');
  chars[index] = current === 'A' ? 'B' : 'A';
  return chars.join('');
}

function enable(): void {
  process.env[FLAG] = '1';
}

function githubFindings(path: string, token: string): Finding[] {
  return scanTextForSecrets(path, `auth("${token}");`).filter((f) => f.ruleId === 'SECRET-GITHUB-001');
}

function result(findings: Finding[]): ScanResult {
  return {
    findings,
    summary: {
      total: findings.length,
      bySeverity: {
        info: 0,
        low: 0,
        medium: findings.filter((row) => row.severity === 'medium').length,
        high: findings.filter((row) => row.severity === 'high').length,
        critical: findings.filter((row) => row.severity === 'critical').length,
      },
    },
    metadata: {
      version: '0.4.0',
      startedAt: '2026-01-01T00:00:00.000Z',
      durationMs: 1,
      cwd: '/tmp/app',
      filesScanned: 1,
      modulesRequested: ['secrets'],
      modulesRun: ['secrets'],
    },
    config: structuredClone(DEFAULT_CONFIG),
  };
}

describe('Phase 82 secret precision', () => {
  const body = 'A1'.repeat(15);
  const valid = classicToken('ghp', body);
  const broken = oneOff(valid, 4);

  it('keeps a generated valid GitHub checksum at the rule confidence', () => {
    enable();
    const found = githubFindings('src/app.js', valid);
    expect(found).toHaveLength(1);
    expect(found[0]?.severity).toBe('high');
    expect(found[0]?.confidence).toBe('high');
    expect(found[0]?.secretCheck).toBeUndefined();
    expect(found[0]?.context).toBeUndefined();
  });

  it('marks a one-character-off token checksum-failed without dropping it or raising severity', () => {
    enable();
    const found = githubFindings('src/app.js', broken);
    expect(found).toHaveLength(1);
    expect(found[0]?.severity).toBe('high');
    expect(found[0]?.confidence).toBe('low');
    expect(found[0]?.secretCheck).toBe('checksum-failed');
    expect(isActionable(found[0]!)).toBe(true);
  });

  it('accepts every documented classic prefix and rejects a one-character edit', () => {
    enable();
    for (const prefix of ['gho', 'ghu', 'ghs', 'ghr'] as const) {
      const token = classicToken(prefix, body);
      const ok = githubFindings('src/app.js', token);
      const bad = githubFindings('src/app.js', oneOff(token, 4));
      expect(ok[0]?.confidence).toBe('high');
      expect(ok[0]?.secretCheck).toBeUndefined();
      expect(bad).toHaveLength(1);
      expect(bad[0]?.confidence).toBe('low');
      expect(bad[0]?.secretCheck).toBe('checksum-failed');
      expect(bad[0]?.severity).toBe('high');
    }
  });

  it('checks github_pat_ only while the flag is on', () => {
    const head = `${'A1'.repeat(11)}_${'A1'.repeat(26)}Z`;
    const token = fineToken(head);
    const off = githubFindings('src/app.js', token);
    expect(off).toHaveLength(0);
    enable();
    const ok = githubFindings('src/app.js', token);
    const bad = githubFindings('src/app.js', oneOff(token, 'github_pat_'.length));
    expect(ok).toHaveLength(1);
    expect(ok[0]?.confidence).toBe('high');
    expect(ok[0]?.secretCheck).toBeUndefined();
    expect(bad).toHaveLength(1);
    expect(bad[0]?.confidence).toBe('low');
    expect(bad[0]?.secretCheck).toBe('checksum-failed');
    expect(bad[0]?.severity).toBe(ok[0]?.severity);
  });

  it('does not run checksum logic on other issuers', () => {
    enable();
    const stripe = 'sk_live_' + 'FAKEfakeFAKEfakeFAKE1234';
    const slack = 'xoxb-' + '1234567890ab-ZZQQQQQQQQQQ';
    const google = 'AIza' + 'A1'.repeat(17) + 'B';
    const aws = 'AKIA' + '23456789ABCDEFGH';
    const text = `pay("${stripe}"); slack("${slack}"); g("${google}"); a("${aws}");`;
    const found = scanTextForSecrets('src/pay.js', text);
    expect(found.map((f) => f.ruleId).sort()).toEqual(
      ['SECRET-AWS-001', 'SECRET-GOOGLE-001', 'SECRET-SLACK-001', 'SECRET-STRIPE-001'].sort(),
    );
    expect(found.every((f) => f.secretCheck === undefined)).toBe(true);
    expect(found.every((f) => f.confidence === 'high')).toBe(true);
    expect(found.every((f) => f.severity === 'high')).toBe(true);
  });

  it('labels placeholder values low and keeps the finding', () => {
    enable();
    const cases: Array<{ text: string; ruleId: string }> = [
      { ruleId: 'SECRET-JWT-001', text: 'jwt_secret = "aaaaaaaa";' },
      { ruleId: 'SECRET-JWT-001', text: 'jwt_secret = "abcdefgh";' },
      { ruleId: 'SECRET-JWT-001', text: 'jwt_secret = "87654321";' },
      { ruleId: 'SECRET-JWT-001', text: 'jwt_secret = "example-value";' },
      { ruleId: 'SECRET-JWT-001', text: 'jwt_secret = "sample-value";' },
      { ruleId: 'SECRET-JWT-001', text: 'jwt_secret = "dummy-value";' },
      { ruleId: 'SECRET-JWT-001', text: 'jwt_secret = "changeme";' },
      { ruleId: 'SECRET-JWT-001', text: 'jwt_secret = "your_api_key";' },
      { ruleId: 'SECRET-JWT-001', text: 'jwt_secret = "aaaaxxxx";' },
      { ruleId: 'SECRET-JWT-001', text: 'jwt_secret = "<placeholder>";' },
      { ruleId: 'SECRET-JWT-001', text: 'jwt_secret = "${MY_SECRET}";' },
      { ruleId: 'SECRET-AWS-001', text: `const k = "${AWS_EXAMPLE}";` },
    ];
    for (const row of cases) {
      const found = scanTextForSecrets('src/app.js', row.text).filter((f) => f.ruleId === row.ruleId);
      expect(found, row.text).toHaveLength(1);
      expect(found[0]?.secretCheck).toBe('placeholder');
      expect(found[0]?.confidence).toBe('low');
      expect(found[0]?.severity === 'high' || found[0]?.severity === 'medium').toBe(true);
    }
  });

  it('leaves a non-placeholder secret at its rule confidence', () => {
    enable();
    const found = scanTextForSecrets('src/app.js', 'jwt_secret = "n0t-a-place-h0lder";').filter(
      (f) => f.ruleId === 'SECRET-JWT-001',
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.confidence).toBe('medium');
    expect(found[0]?.severity).toBe('medium');
    expect(found[0]?.secretCheck).toBeUndefined();
  });

  it('lowers confidence one step for test and fixture paths', () => {
    enable();
    const positive = [
      'test/app.js',
      'src/test/app.js',
      '__tests__/app.js',
      'src/__tests__/app.js',
      'fixtures/app.js',
      'src/fixtures/app.js',
      'app.test.js',
      'src/app.spec.ts',
      'config.example',
      'dir/config.sample',
      'test\\app.js',
    ];
    for (const path of positive) {
      const found = githubFindings(path, valid);
      expect(found[0]?.context, path).toBe('test');
      expect(found[0]?.confidence, path).toBe('medium');
      expect(found[0]?.severity, path).toBe('high');
      expect(found[0]?.secretCheck, path).toBeUndefined();
    }
    const negative = [
      'src/app.js',
      'contest/app.js',
      'src/latest/app.js',
      'myfixtures/app.js',
      'app.testing.js',
      'app.spec',
      'sample.js',
      'tests/app.js',
      'src/testfile.js',
      'file.example.js',
    ];
    for (const path of negative) {
      const found = githubFindings(path, valid);
      expect(found[0]?.context, path).toBeUndefined();
      expect(found[0]?.confidence, path).toBe('high');
    }
  });

  it('floors an already-low secret and steps a medium secret down in test files', () => {
    enable();
    const jwt = scanTextForSecrets('test/auth.js', 'jwt_secret = "n0t-a-place-h0lder";').find(
      (f) => f.ruleId === 'SECRET-JWT-001',
    );
    expect(jwt?.confidence).toBe('low');
    expect(jwt?.context).toBe('test');
    expect(jwt?.severity).toBe('medium');
    const value = 'aB3dE5gH7jK9mN1pQ4sU6wX8';
    const entropy = scanTextForSecrets('test/app.js', `const apiKey = "${value}";`).find(
      (f) => f.ruleId === 'SECRET-ENTROPY-001',
    );
    expect(entropy?.confidence).toBe('low');
    expect(entropy?.context).toBe('test');
    expect(entropy?.severity).toBe('medium');
    const pem = scanTextForSecrets('test/key.pem', '-----BEGIN PRIVATE KEY-----').find(
      (f) => f.ruleId === 'SECRET-PRIVKEY-001',
    );
    expect(pem?.confidence).toBe('medium');
    expect(pem?.context).toBe('test');
    expect(pem?.secretCheck).toBeUndefined();
    expect(pem?.severity).toBe('critical');
  });

  it('prefers placeholder when a checksum also fails', () => {
    enable();
    const noisyBody = 'example' + 'A1'.repeat(11) + 'A';
    const noisy = `ghp_${noisyBody}AAAAAA`;
    expect(base62Crc(noisyBody)).not.toBe('AAAAAA');
    const found = githubFindings('src/app.js', noisy);
    expect(found).toHaveLength(1);
    expect(found[0]?.secretCheck).toBe('placeholder');
    expect(found[0]?.confidence).toBe('low');
    expect(found[0]?.severity).toBe('high');
  });

  it('folds low-confidence secrets below high severity in the console and keeps them in JSON', () => {
    enable();
    const jwt = scanTextForSecrets('src/jwt.js', 'jwt_secret = "changeme";').find(
      (f) => f.ruleId === 'SECRET-JWT-001',
    );
    const github = githubFindings('src/live.js', broken)[0];
    expect(jwt).toBeDefined();
    expect(github).toBeDefined();
    expect(isActionable(jwt!)).toBe(false);
    expect(isActionable(github!)).toBe(true);
    const text = renderConsoleReport(result([jwt!, github!]));
    const json = JSON.parse(renderJsonReport(result([jwt!, github!]))) as { findings: Finding[] };
    expect(text).toContain('src/live.js:1');
    expect(text).not.toContain('src/jwt.js:1');
    expect(text).toContain('1 more (not directly reachable, or below high confidence) — --all or --markdown report.md');
    expect(json.findings).toHaveLength(2);
    expect(json.findings.find((f) => f.ruleId === 'SECRET-JWT-001')?.confidence).toBe('low');
    expect(json.findings.find((f) => f.ruleId === 'SECRET-JWT-001')?.secretCheck).toBe('placeholder');
  });

  it('matches flag-off output with the flag unset, including severity', () => {
    const text = [
      `auth("${broken}");`,
      `auth("${valid}");`,
      'jwt_secret = "changeme";',
      `const k = "${AWS_EXAMPLE}";`,
      '-----BEGIN PRIVATE KEY-----',
    ].join('\n');
    const path = 'test/app.js';
    const off = scanTextForSecrets(path, text);
    const again = scanTextForSecrets(path, text);
    expect(off).toEqual(again);
    expect(off.every((f) => f.secretCheck === undefined && f.context === undefined)).toBe(true);
    expect(off.find((f) => f.ruleId === 'SECRET-GITHUB-001' && f.snippet?.startsWith('ghp_'))?.confidence).toBe(
      'high',
    );
    enable();
    const on = scanTextForSecrets(path, text);
    expect(on.map((f) => [f.ruleId, f.file, f.line, f.severity, f.id])).toEqual(
      off.map((f) => [f.ruleId, f.file, f.line, f.severity, f.id]),
    );
    expect(on.some((f) => f.secretCheck !== undefined)).toBe(true);
    expect(on.every((f) => f.context === 'test')).toBe(true);
  });
});
