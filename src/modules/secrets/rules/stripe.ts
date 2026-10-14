import { everyMatch } from '../mask.js';
import type { SecretsRule } from '../types.js';

const PATTERN = /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g;

export const stripeRule: SecretsRule = {
  meta: {
    id: 'SECRET-STRIPE-001',
    title: 'Hardcoded Stripe secret key',
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
