import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { aiPrecision } from '../../../src/ai/logic.js';
import { scan } from '../../../src/core/engine.js';
import { failsCi } from '../../../src/core/finding.js';

const logicApp = join(process.cwd(), 'test', 'fixtures', 'ai-logic-app');
const logicClean = join(process.cwd(), 'test', 'fixtures', 'ai-logic-clean');

describe('AI logic hunter (Phase 16)', () => {
  beforeEach(() => {
    process.env.FULLSHIELD_AI_INTERNAL = '1';
  });
  afterEach(() => {
    delete process.env.FULLSHIELD_AI_INTERNAL;
  });

  it('does not run from the public scan() API without the internal flag', async () => {
    delete process.env.FULLSHIELD_AI_INTERNAL;
    const result = await scan({ cwd: logicApp, offline: true, ai: 'logic' });
    expect(result.findings.some((f) => f.ruleId === 'AI-IDOR-001')).toBe(false);
  });

  it('flags seeded IDOR and mass-assignment as source:ai confidence medium', async () => {
    const result = await scan({ cwd: logicApp, offline: true, ai: 'logic' });
    const idor = result.findings.find((f) => f.ruleId === 'AI-IDOR-001');
    const mass = result.findings.find((f) => f.ruleId === 'AI-MASSASSIGN-001');
    expect(idor?.source).toBe('ai');
    expect(idor?.confidence).toBe('medium');
    expect(idor?.severity).toBe('medium');
    expect(mass?.source).toBe('ai');
    expect(mass?.confidence).toBe('medium');
    expect(
      result.findings.filter((f) => failsCi(f, 'high')).map((f) => `${f.ruleId}:${f.severity}:${f.source}:${f.file}`),
    ).toEqual([]);
    expect(aiPrecision(result.findings, ['AI-IDOR-001', 'AI-MASSASSIGN-001'])).toBe(1);
  });

  it('does not flag the clean ownership-checked equivalents', async () => {
    const result = await scan({ cwd: logicClean, offline: true, ai: 'logic' });
    expect(result.findings.some((f) => f.ruleId === 'AI-IDOR-001')).toBe(false);
    expect(result.findings.some((f) => f.ruleId === 'AI-MASSASSIGN-001')).toBe(false);
  });
});
