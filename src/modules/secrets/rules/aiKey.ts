import { everyMatch } from '../mask.js';
import type { SecretsRule } from '../types.js';

// Anthropic-style first (sk-ant-...), then generic OpenAI-style sk-... keys.
const PATTERN = /\bsk-ant-[A-Za-z0-9_-]{16,}\b|\bsk-[A-Za-z0-9_-]{20,}\b/g;

export const aiKeyRule: SecretsRule = {
  meta: {
    id: 'SECRET-AIKEY-001',
    title: 'Hardcoded AI provider API key (OpenAI/Anthropic-style)',
    severity: 'high',
    confidence: 'high',
    cwe: 'CWE-798',
  },
  check(ctx) {
    ctx.lines.forEach((line, index) => {
      for (const match of everyMatch(PATTERN, line)) {
        ctx.report({ line: index + 1, secret: match[0] });
      }
    });
  },
};
