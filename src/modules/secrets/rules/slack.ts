import { everyMatch } from '../mask.js';
import type { SecretsRule } from '../types.js';

const PATTERN = /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g;

export const slackRule: SecretsRule = {
  meta: {
    id: 'SECRET-SLACK-001',
    title: 'Hardcoded Slack token',
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
