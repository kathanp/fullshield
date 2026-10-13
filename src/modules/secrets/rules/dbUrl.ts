import type { SecretsRule } from '../types.js';

const PATTERN =
  /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp):\/\/([^\s'"@/:]+):([^\s'"@]+)@/g;

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
      for (const match of line.matchAll(PATTERN)) {
        const password = match[2];
        // Template placeholders (`:${password}@`) are not hardcoded secrets.
        if (password === undefined || password.includes('${')) continue;
        ctx.report({ line: index + 1, secret: password });
      }
    });
  },
};
