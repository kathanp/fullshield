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
  it('adds helmet() after express()', () => {
    const src = `const express = require('express');\nconst app = express();\n`;
    const fix = proposeFix(finding('CONFIG-HELMET-001', 'src/index.js'), src);
    expect(fix?.safe).toBe(true);
    expect(fix?.diff).toContain("require('helmet')");
    expect(fix?.diff).toContain('app.use(helmet())');
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
    expect(fix?.diff).toContain('randomUUID()');
    expect(fix?.diff).toContain('Math.random()');
  });

  it('appends .env to gitignore', () => {
    const src = `node_modules/\n`;
    const fix = proposeFix(finding('SECRET-ENVFILE-001', '.gitignore'), src);
    expect(fix?.safe).toBe(true);
    expect(fix?.diff).toContain('.env');
  });
});
