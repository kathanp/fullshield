import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { FLAG, SAM_AUTH, SAM_IAM, SAM_SECRET, scanSam } from '../../../src/phases/p457.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const token = `AKIA${'Z'.repeat(16)}`;

describe('phase 457', () => {
  it('reports a star action and an unauthenticated session route', () => {
    process.env[FLAG] = '1';
    const text = `functions:\n  app:\n    events:\n      - http:\n          path: /session\n          method: get\n    iamRoleStatements:\n      - Effect: Allow\n        Action: '*'\n        Resource: arn:aws:s3:::b\n`;
    const result = scanSam('serverless.yml', text, [{ path: '/session', auth: 'session' }]);
    expect(result.findings.some((row) => row.ruleId === SAM_IAM)).toBe(true);
    expect(result.findings.some((row) => row.ruleId === SAM_AUTH)).toBe(true);
  });

  it('ignores a scoped action, a public pair, and a comment', () => {
    process.env[FLAG] = '1';
    const scoped = `functions:\n  app:\n    events:\n      - http:\n          path: /health\n          method: get\n    iamRoleStatements:\n      - Action: s3:GetObject\n        Resource: arn:aws:s3:::b\n# Action: '*'\n`;
    const result = scanSam('serverless.yml', scoped, [{ path: '/health', auth: 'public' }]);
    expect(result.findings.some((row) => row.ruleId === SAM_IAM)).toBe(false);
    expect(result.findings.some((row) => row.ruleId === SAM_AUTH)).toBe(false);
  });

  it('reports a token literal and an unresolved ref without calling it public', () => {
    process.env[FLAG] = '1';
    const result = scanSam('template.yaml', `Env: ${token}\nRef: !Ref Bucket\n`, []);
    expect(result.findings.some((row) => row.ruleId === SAM_SECRET)).toBe(true);
    expect(result.events.length).toBeGreaterThan(0);
    expect(result.findings.some((row) => row.ruleId === SAM_AUTH)).toBe(false);
    const src = readFileSync(join(root, 'src/phases/p457.ts'), 'utf8');
    expect(src.includes('@aws-sdk')).toBe(false);
    expect(src.includes('aws-sdk')).toBe(false);
  });

  it('returns the baseline when the flag is off', () => {
    const baseline = [{ ruleId: 'kept', severity: 'info' as const, file: 'serverless.yml', line: 1, message: 'kept' }];
    expect(scanSam('serverless.yml', "Action: '*'\n", [], baseline).findings).toEqual(baseline);
  });
});
