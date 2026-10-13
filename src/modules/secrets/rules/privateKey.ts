import type { SecretsRule } from '../types.js';

const PATTERN = /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----/;

export const privateKeyRule: SecretsRule = {
  meta: {
    id: 'SECRET-PRIVKEY-001',
    title: 'Private key material committed to the repository',
    severity: 'critical',
    confidence: 'high',
    cwe: 'CWE-321',
  },
  check(ctx) {
    ctx.lines.forEach((line, index) => {
      if (PATTERN.test(line)) {
        ctx.report({
          line: index + 1,
          message: 'A PEM private key block is committed to the repository.',
        });
      }
    });
  },
};
