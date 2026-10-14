import { everyMatch } from '../mask.js';
import type { SecretsRule } from '../types.js';

const PATTERN = /\bAIza[0-9A-Za-z_-]{35}\b/g;

export const googleRule: SecretsRule = {
  meta: {
    id: 'SECRET-GOOGLE-001',
    title: 'Hardcoded Google API key',
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
