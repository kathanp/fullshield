import { shannonEntropy } from '../mask.js';
import type { SecretsRule } from '../types.js';

const ASSIGNMENT = /\b([A-Za-z_$][\w$]*)\s*[:=]\s*["'`]([^"'`]{20,})["'`]/g;
const SECRET_NAME = /(key|secret|token|passw(or)?d|pwd|credential)/i;
const ENTROPY_THRESHOLD = 4.5;

export const entropyRule: SecretsRule = {
  meta: {
    id: 'SECRET-ENTROPY-001',
    title: 'High-entropy string assigned to a secret-like variable',
    severity: 'medium',
    confidence: 'low',
    cwe: 'CWE-798',
  },
  check(ctx) {
    ctx.lines.forEach((line, index) => {
      for (const match of line.matchAll(ASSIGNMENT)) {
        const [, name, value] = match;
        if (name === undefined || value === undefined) continue;
        if (!SECRET_NAME.test(name)) continue;
        if (value.includes(' ') || value.includes('${')) continue;
        if (shannonEntropy(value) <= ENTROPY_THRESHOLD) continue;
        ctx.report({ line: index + 1, secret: value });
      }
    });
  },
};
