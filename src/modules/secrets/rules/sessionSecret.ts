import { everyMatch } from '../mask.js';
import type { SecretsRule } from '../types.js';

const SECRET_PROP = /\bsecret\s*:\s*['"`]([^'"`]{3,})['"`]/g;

export const sessionSecretRule: SecretsRule = {
  meta: {
    id: 'SECRET-SESSION-001',
    title: 'Hardcoded express-session secret',
    severity: 'medium',
    confidence: 'medium',
    cwe: 'CWE-798',
  },
  check(ctx) {
    let pending = 0;
    ctx.lines.forEach((line, index) => {
      if (/\bsession\s*\(/.test(line)) {pending = 8;}
      if (pending <= 0) {return;}
      pending -= 1;
      for (const match of everyMatch(SECRET_PROP, line)) {
        const secret = match[1];
        if (secret !== undefined) {
          ctx.report({ line: index + 1, secret });
        }
      }
    });
  },
};
