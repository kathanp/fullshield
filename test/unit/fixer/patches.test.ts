import { describe, expect, it } from 'vitest';

import { proposeFix } from '../../../src/fixer/patches.js';
import { makeFindingId, type Finding } from '../../../src/core/finding.js';

function finding(ruleId: string, file: string): Finding {
  return {
    id: makeFindingId(ruleId, file, ruleId),
    ruleId,
    module: ruleId.startsWith('CONFIG') ? 'config' : ruleId.startsWith('SECRET') ? 'secrets' : 'sast',
    title: ruleId,
    severity: 'high',
    confidence: 'high',
    file,
    line: 1,
    message: ruleId,
    remediation: 'fix',
  };
}

describe('proposeFix (safe v1 patches)', () => {
  it('adds helmet() after express() as an unsafe suggestion', () => {
    const src = `const express = require('express');\nconst app = express();\n`;
    const fix = proposeFix(finding('CONFIG-HELMET-001', 'src/index.js'), src);
    expect(fix?.safe).toBe(false);
    expect(fix?.diff).toContain("require('helmet')");
    expect(fix?.diff).toContain('app.use(helmet())');
  });

  it('does not propose helmet when it is already applied', () => {
    const src = `const helmet = require('helmet');\nconst app = express();\napp.use(helmet());\n`;
    expect(proposeFix(finding('CONFIG-HELMET-001', 'src/index.js'), src)).toBeUndefined();
  });

  it('adds a json body limit', () => {
    const src = `app.use(express.json());\n`;
    const fix = proposeFix(finding('CONFIG-BODYLIMIT-001', 'src/index.js'), src);
    expect(fix?.safe).toBe(true);
    expect(fix?.diff).toContain("express.json({ limit: '100kb' })");
  });

  it('replaces Math.random token generation with crypto.randomUUID', () => {
    const src = `const sessionToken = Math.random().toString(36).slice(2);\n`;
    const fix = proposeFix(finding('SAST-CRYPTO-001', 'src/index.js'), src);
    expect(fix?.safe).toBe(true);
    expect(fix?.diff).toContain("require('crypto')");
    expect(fix?.diff).toContain('randomUUID()');
    expect(fix?.diff).toContain('Math.random()');
    const already = `const crypto = require('crypto');\nconst sessionToken = Math.random().toString(36).slice(2);\n`;
    const again = proposeFix(finding('SAST-CRYPTO-001', 'src/index.js'), already);
    expect(again?.diff).toContain('randomUUID()');
  });

  it('appends .env to gitignore', () => {
    const src = `node_modules/\n`;
    const fix = proposeFix(finding('SECRET-ENVFILE-001', '.gitignore'), src);
    expect(fix?.safe).toBe(true);
    expect(fix?.diff).toContain('.env');
    const noNl = proposeFix(finding('SECRET-ENVFILE-001', '.env'), 'node_modules');
    expect(noNl?.diff).toContain('.env');
  });

  it('does not append .env when gitignore already lists it', () => {
    expect(proposeFix(finding('SECRET-ENVFILE-001', '.gitignore'), 'node_modules/\n.env\n')).toBeUndefined();
  });

  it('replaces a secret literal with process.env as an unsafe suggestion', () => {
    const src = `const key = 'sk_live_placeholder';\n`;
    const f = finding('SECRET-STRIPE-001', 'src/keys.js');
    const fix = proposeFix(f, src);
    expect(fix?.safe).toBe(false);
    expect(fix?.diff).toContain('process.env.STRIPE_SECRET_KEY');
    expect(fix?.diff).toContain('TODO: rotate');
  });

  it('maps secret rule ids to env names and returns the attached finding.fix when present', () => {
    const src = `const v = 'x';\n`;
    for (const [ruleId, env] of [
      ['SECRET-AWS-001', 'AWS_ACCESS_KEY_ID'],
      ['SECRET-JWT-001', 'JWT_SECRET'],
      ['SECRET-GITHUB-001', 'GITHUB_TOKEN'],
      ['SECRET-SLACK-001', 'SLACK_TOKEN'],
      ['SECRET-GOOGLE-001', 'GOOGLE_API_KEY'],
      ['SECRET-AIKEY-001', 'AI_API_KEY'],
      ['SECRET-DBURL-001', 'DATABASE_URL'],
      ['SECRET-PRIVKEY-001', 'SECRET'],
    ] as const) {
      const fix = proposeFix(finding(ruleId, 'a.js'), src);
      expect(fix?.safe).toBe(false);
      expect(fix?.diff).toContain(`process.env.${env}`);
    }
    const attached = finding('SAST-SQLI-001', 'a.js');
    attached.fix = { kind: 'code-patch', safe: true, diff: '--- a\n+++ b\n' };
    expect(proposeFix(attached, src)).toEqual(attached.fix);
  });

  it('skips secret replacement when the finding line is not an assignment', () => {
    const f = finding('SECRET-STRIPE-001', 'src/keys.js');
    f.line = 2;
    expect(proposeFix(f, 'const x = 1;\n// comment only\n')).toBeUndefined();
    f.line = 99;
    expect(proposeFix(f, 'const x = 1;\n')).toBeUndefined();
  });

  it('skips body-limit and crypto patches when the pattern is absent', () => {
    expect(proposeFix(finding('CONFIG-BODYLIMIT-001', 'a.js'), 'const x = 1;\n')).toBeUndefined();
    expect(proposeFix(finding('SAST-CRYPTO-001', 'a.js'), 'const x = 1;\n')).toBeUndefined();
  });

  it('returns undefined for rules without a v1 patch and for helmet with no express() factory', () => {
    expect(proposeFix(finding('SAST-SQLI-001', 'a.js'), 'const x = 1;\n')).toBeUndefined();
    expect(
      proposeFix(
        finding('CONFIG-HELMET-001', 'r.js'),
        `const helmet = require('helmet');\nconst r = express.Router();\n`,
      ),
    ).toBeUndefined();
  });
});

describe('applyUnifiedDiff', () => {
  it('rebuilds a file from plus-lines and leaves source unchanged when there are none', async () => {
    const { applyUnifiedDiff } = await import('../../../src/fixer/patches.js');
    expect(applyUnifiedDiff('old\n', '--- a/f\n+++ b/f\n+new\n')).toBe('new');
    expect(applyUnifiedDiff('old\n', '--- a/f\n+++ b/f\n')).toBe('old\n');
  });
});
