import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runAiFix } from '../../../src/ai/fixLoop.js';
import { createAiClient } from '../../../src/ai/provider.js';
import { scan } from '../../../src/core/engine.js';

const injectApp = join(process.cwd(), 'test', 'fixtures', 'ai-inject-app');
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');

describe('AI triage / explain / fix (Phase 15)', () => {
  beforeEach(() => {
    process.env.FULLSHIELD_AI_INTERNAL = '1';
  });
  afterEach(() => {
    delete process.env.FULLSHIELD_AI_INTERNAL;
  });

  it('does not run triage from the public scan() API without the internal flag', async () => {
    delete process.env.FULLSHIELD_AI_INTERNAL;
    const result = await scan({ cwd: vulnerableApp, offline: true, ai: 'triage' });
    expect(result.findings.every((f) => f.aiVerdict === undefined)).toBe(true);
  });

  it('labels findings and never removes a high or critical true positive', async () => {
    const result = await scan({ cwd: vulnerableApp, offline: true, ai: 'triage' });
    const sqli = result.findings.filter((f) => f.ruleId === 'SAST-SQLI-001');
    expect(sqli.length).toBeGreaterThan(0);
    expect(sqli.every((f) => f.aiVerdict === 'true-positive')).toBe(true);
    expect(sqli.every((f) => f.severity === 'high')).toBe(true);
    const highs = result.findings.filter((f) => f.severity === 'high' || f.severity === 'critical');
    expect(highs.length).toBeGreaterThan(0);
    expect(highs.every((f) => f.source !== 'ai')).toBe(true);
  });

  it('adds a plain-English explanation without changing the finding set', async () => {
    const base = await scan({ cwd: injectApp, offline: true });
    const explained = await scan({ cwd: injectApp, offline: true, ai: 'explain' });
    expect(explained.findings.map((f) => f.id).sort()).toEqual(base.findings.map((f) => f.id).sort());
    const inject = explained.findings.find((f) => f.ruleId === 'AI-INJECT-001');
    expect(inject?.explanation).toMatch(/comment|AI/i);
    expect(explained.findings.every((f) => f.aiVerdict === undefined)).toBe(true);
  });

  it('keeps a verified AI patch as a reviewable diff and does not write the user tree', async () => {
    const { readFile } = await import('node:fs/promises');
    const before = await readFile(join(injectApp, 'src', 'index.js'), 'utf8');
    const client = createAiClient({ enabled: true, useFixtures: true });
    const fix = await runAiFix({ cwd: injectApp, client });
    expect(fix.accepted).toBe(true);
    expect(fix.diff).toContain('--- a/src/index.js');
    expect(fix.attempts).toBeLessThanOrEqual(2);
    const after = await readFile(join(injectApp, 'src', 'index.js'), 'utf8');
    expect(after).toBe(before);
    expect(before).toContain('ignore previous');
  });
});
