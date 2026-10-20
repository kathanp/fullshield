import { everyMatch } from '../mask.js';
import type { SecretsRule } from '../types.js';

const PATTERN =
  /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp):\/\/([^\s'"@/:]+):([^\s'"@]+)@/g;

function isPlaceholderPassword(password: string): boolean {
  if (password.includes('${')) {return true;}
  if (/^<[^>]+>$/.test(password)) {return true;}
  if (/^\{[^}]+\}$/.test(password)) {return true;}
  return false;
}

export const dbUrlRule: SecretsRule = {
  meta: {
    id: 'SECRET-DBURL-001',
    title: 'Database connection string with inline password',
    severity: 'high',
    confidence: 'high',
    cwe: 'CWE-798',
  },
  check(ctx) {
    ctx.lines.forEach((line, index) => {
      for (const match of everyMatch(PATTERN, line)) {
        const password = match[2];
        // Template placeholders (`:${password}@`) and docs tokens (`<password>`)
        // are not hardcoded secrets.
        if (password === undefined || isPlaceholderPassword(password)) {continue;}
        ctx.report({ line: index + 1, secret: password });
      }
    });
  },
};
