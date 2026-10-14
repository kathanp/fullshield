import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { scanLlmApp } from '../../../src/llm/index.js';

const fixtures = join(dirname(fileURLToPath(import.meta.url)), '../../fixtures');

describe('Phase 21 LLM-app rules (experimental)', () => {
  it('flags user input concatenated into a system prompt', () => {
    const findings = scanLlmApp(join(fixtures, 'llm-app'), { experimental: true });
    expect(findings.some((f) => f.ruleId === 'LLM-001')).toBe(true);
  });

  it('flags LLM output passed into exec', () => {
    const findings = scanLlmApp(join(fixtures, 'llm-app'), { experimental: true });
    expect(findings.some((f) => f.ruleId === 'LLM-002')).toBe(true);
  });

  it('flags a shell tool without confirmation', () => {
    const findings = scanLlmApp(join(fixtures, 'llm-app'), { experimental: true });
    expect(findings.some((f) => f.ruleId === 'LLM-003')).toBe(true);
  });

  it('flags an API key in a browser/public bundle file', () => {
    const findings = scanLlmApp(join(fixtures, 'llm-app'), { experimental: true });
    expect(findings.some((f) => f.ruleId === 'LLM-004')).toBe(true);
  });

  it('flags an LLM call without max_tokens / cost limit', () => {
    const findings = scanLlmApp(join(fixtures, 'llm-app'), { experimental: true });
    expect(findings.some((f) => f.ruleId === 'LLM-005')).toBe(true);
  });

  it('does not flag the negative fixture', () => {
    const findings = scanLlmApp(join(fixtures, 'llm-clean'), { experimental: true });
    expect(findings).toEqual([]);
  });

  it('is a no-op without experimental', () => {
    const findings = scanLlmApp(join(fixtures, 'llm-app'));
    expect(findings).toEqual([]);
  });
});
