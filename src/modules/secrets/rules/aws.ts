import type { SecretsRule } from '../types.js';

const PATTERN = /\bAKIA[0-9A-Z]{16}\b/g;

export const awsRule: SecretsRule = {
  meta: {
    id: 'SECRET-AWS-001',
    title: 'Hardcoded AWS access key ID',
    severity: 'high',
    confidence: 'high',
    cwe: 'CWE-798',
  },
  check(ctx) {
    ctx.lines.forEach((line, index) => {
      for (const match of line.matchAll(PATTERN)) {
        ctx.report({ line: index + 1, secret: match[0] });
      }
    });
  },
};
