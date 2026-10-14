import { everyMatch } from '../mask.js';
import type { SecretsRule } from '../types.js';

const PATTERN =
  /\b(?:jwt[_-]?secret|jwt[_-]?key|token[_-]?secret|signing[_-]?key)\b\s*[:=]\s*["'`]([^"'`]{8,})["'`]/gi;

export const jwtSecretRule: SecretsRule = {
  meta: {
    id: 'SECRET-JWT-001',
    title: 'JWT secret assigned from a string literal',
    severity: 'medium',
    confidence: 'medium',
    cwe: 'CWE-798',
  },
  check(ctx) {
    ctx.lines.forEach((line, index) => {
      for (const match of everyMatch(PATTERN, line)) {
        const secret = match[1];
        if (secret !== undefined) {
          ctx.report({ line: index + 1, secret });
        }
      }
    });
  },
};
