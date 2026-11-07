import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { scanLlmApp } from '../../../src/llm/index.js';

const fixtures = join(dirname(fileURLToPath(import.meta.url)), '../../fixtures');

describe('LLM-001 through LLM-005 are not reported', () => {
  it('reports nothing for the old positive fixture, with or without the removed flag', () => {
    expect(scanLlmApp(join(fixtures, 'llm-app'), { experimental: true })).toEqual([]);
    expect(scanLlmApp(join(fixtures, 'llm-app'))).toEqual([]);
    expect(scanLlmApp(join(fixtures, 'llm-clean'), { experimental: true })).toEqual([]);
  });
});
